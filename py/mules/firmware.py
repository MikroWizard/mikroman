#!/usr/bin/python
# -*- coding: utf-8 -*-

# firmware.py: firmware update scheduler (uWSGI mule)
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com
#
# Runs every firmware request (manual, group, scheduled task, automatic retry, next step of
# a multi-step upgrade, RouterBOOT) and verifies routers after their update reboot.
# Requests are queued by bgtasks / task_run (libs/firm_lib.enqueue_device_updates); the
# per-device state lives in Redis (libs/fw_state.py) so nothing is lost when a process
# restarts, and a per-device lease guarantees one worker per router.
#
# The loop never waits for a single router: verification and update work run in two
# thread pools and the loop only submits new jobs every TICK_SECONDS.

import time
import concurrent.futures
from libs import util, firm_lib, fw_state, job_control, retention, logsetup, audit_redact_backfill
from libs.db import db_tasks, db_device
from libs.db.db import database, tune_process_db_pool
import config
import logging
import os

log = logging.getLogger("Firmware")

try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False

logsetup.init_logging()   # same log output in the free tier (Pro gets it via libs.webutil)

TICK_SECONDS = 15
VERIFY_WORKERS = 8
FIRMWARE_PROGRESS_LOG_SECONDS = 300


def get_dynamic_firmware_workers(num_devices):
    """Concurrent update jobs. Each job mostly waits for the router (download, reboot is
    not waited for), but every job also uses one of FIRMWARE_MAX_TRANSFERS download slots."""
    base_limit = getattr(config, "FIRMWARE_CONCURRENCY", 30)
    if num_devices <= 20:
        workers = min(num_devices, 8)
    elif num_devices <= 100:
        workers = min(num_devices, 15)
    elif num_devices <= 500:
        workers = min(num_devices, 25)
    else:
        workers = min(num_devices, 35)
    return max(1, min(workers, base_limit))


def _wait_with_progress(futures, label):
    """Wait for all futures, logging the devices still in progress every few minutes
    (kept for callers that run a batch synchronously)."""
    pending = set(futures)
    started = time.time()
    while pending:
        done, pending = concurrent.futures.wait(pending, timeout=FIRMWARE_PROGRESS_LOG_SECONDS)
        for f in done:
            exc = f.exception()
            if exc is not None:
                dev = futures[f]
                log.error(f"{label} worker failed for dev {getattr(dev, 'id', '?')} ({getattr(dev, 'ip', '')}): {exc}")
        if pending:
            still = [futures[f] for f in pending]
            log.info(f"{label}: {len(still)} device(s) still in progress after {int(time.time() - started)}s: "
                     f"{[getattr(d, 'ip', '?') for d in still[:20]]}")


def _sysconfig_flags():
    max_retries = firm_lib._max_retries()
    auto_retry = firm_lib._sysconf('firmware_auto_retry', 'True') != 'False'
    return max_retries, auto_retry


def plan_actions(devices, records, leased, now, max_retries, auto_retry, inflight=()):
    """Decide what to do for each device: [(dev, 'verify' | 'work' | 'expire' | 'recover')].

    devices : Devices rows (status, firmware_to_install, failed_attempt, upgrade_device)
    records : {dev_id: record} from fw_state
    leased  : dev ids with a lease (someone is working on them)
    """
    actions = []
    for dev in devices:
        if dev.id in inflight or dev.id in leased:
            continue
        rec = records.get(dev.id) or {}
        state = rec.get("state")
        status = dev.status or ""
        if state == "rebooting" or status in ("rebooting", "upgrading"):
            actions.append((dev, "verify"))
            continue
        if status == "updated" and dev.firmware_to_install:
            actions.append((dev, "verify"))
            continue
        due = now >= float(rec.get("next_try_at") or 0)
        if state == "queued":
            max_age = int(getattr(config, "FIRMWARE_QUEUE_MAX_AGE", 24 * 3600))
            if now - float(rec.get("queued_at") or now) > max_age:
                actions.append((dev, "expire"))
            elif due:
                actions.append((dev, "work"))
            continue
        if state == "next_step":
            if due:
                actions.append((dev, "work"))
            continue
        if status == "updating":
            # updating without a lease: the process that worked on it stopped
            # (restart, harakiri, crash) - start it again from the router's real state
            if due:
                actions.append((dev, "recover"))
            continue
        if status == "failed" and dev.firmware_to_install and auto_retry:
            if (dev.failed_attempt or 0) < max_retries and not rec.get("permanent") and due:
                actions.append((dev, "work"))
            continue
    return actions


class FirmwareScheduler(object):
    def __init__(self, work_workers=None, verify_workers=VERIFY_WORKERS):
        self.work_workers = work_workers or get_dynamic_firmware_workers(10 ** 6)
        self.work_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.work_workers,
                                                               thread_name_prefix="fw-work")
        self.verify_pool = concurrent.futures.ThreadPoolExecutor(max_workers=verify_workers,
                                                                 thread_name_prefix="fw-verify")
        self.inflight = {}           # dev_id -> (future, kind)
        self._busy_flag = None

    def _reap(self):
        for dev_id, (fut, kind) in list(self.inflight.items()):
            if fut.done():
                exc = fut.exception()
                if exc is not None:
                    log.error(f"Firmware {kind} job for device {dev_id} failed: {exc}")
                self.inflight.pop(dev_id, None)

    def _candidates(self):
        D = db_device.Devices
        with database.connection_context():
            return list(D.select(D.id, D.name, D.ip, D.port, D.status, D.firmware_to_install, D.failed_attempt,
                                 D.upgrade_device, D.ssl, D.device_type).where(
                D.status.in_(["updating", "rebooting", "upgrading", "failed", "updated"]) |
                D.firmware_to_install.is_null(False)))

    def _set_busy(self, busy):
        if self._busy_flag == busy:
            return
        try:
            with database.connection_context():
                task = db_tasks.firmware_service_status()
                task.status = 1 if busy else 0
                task.save()
            self._busy_flag = busy
        except Exception as e:
            log.warning(f"Could not update firmware service status: {e}")

    def tick(self, now=None):
        now = time.time() if now is None else now
        self._reap()
        devices = self._candidates()
        ids = [d.id for d in devices]
        records = fw_state.get_records(ids)
        # devices a backup / snippet / sequence job is working on wait for the next tick
        leased = fw_state.leased_ids(ids) | job_control.locked_ids(ids)
        max_retries, auto_retry = _sysconfig_flags()
        actions = plan_actions(devices, records, leased, now, max_retries, auto_retry, self.inflight)
        # queued work in request order (Pro: stations before access points)
        actions.sort(key=lambda a: (a[1] != "verify", (records.get(a[0].id) or {}).get("seq", 0)))
        work_running = sum(1 for _, k in self.inflight.values() if k != "verify")
        verify_running = sum(1 for _, k in self.inflight.values() if k == "verify")
        for dev, action in actions:
            if action == "expire":
                self._expire(dev)
                continue
            if action == "verify":
                if verify_running >= VERIFY_WORKERS * 4:
                    continue
                self.inflight[dev.id] = (self.verify_pool.submit(self._verify_job, dev), "verify")
                verify_running += 1
                continue
            if work_running >= self.work_workers:
                continue
            self.inflight[dev.id] = (self.work_pool.submit(self._work_job, dev.id, action), action)
            work_running += 1
        self._set_busy(bool(self.inflight))
        return actions

    @staticmethod
    def _verify_job(dev):
        try:
            return firm_lib.verify_device_firmware(dev)
        finally:
            database.close()

    @staticmethod
    def _work_job(dev_id, action):
        try:
            if action == "recover":
                rec = fw_state.get_record(dev_id) or {}
                dev = firm_lib._load_dev(dev_id)
                if dev is None:
                    return False
                if not rec and not dev.firmware_to_install:
                    # nothing tells which version was requested: never guess - give the
                    # device back (the operator can start the update again)
                    log.warning(f"Device {dev_id} was left 'updating' without an update record - status reset")
                    firm_lib._dev_update(dev_id, status="active")
                    return False
                rec["recoveries"] = int(rec.get("recoveries") or 0) + 1
                if rec["recoveries"] > firm_lib.MAX_RECOVERIES:
                    firm_lib._fail(dev, "Firmware update was interrupted {} times (process restarts) - stopped".format(
                        firm_lib.MAX_RECOVERIES), permanent=True)
                    return False
                if rec.get("state") not in ("queued", "next_step"):
                    rec["state"] = "next_step"
                fw_state.put_record(dev_id, rec)
                log.warning(f"Resuming interrupted firmware update of device {dev_id} (recovery {rec['recoveries']})")
            return firm_lib.run_queued_request(dev_id)
        finally:
            database.close()

    @staticmethod
    def _expire(dev):
        """Queued request older than FIRMWARE_QUEUE_MAX_AGE (router never reachable): drop it
        and give the device its previous state back."""
        if firm_lib.cancel_queued_updates([dev.id]):
            firm_lib._event(dev.id, "Update Failed", "Error",
                            "Queued firmware update dropped: device was not reachable for {} h".format(
                                int(getattr(config, "FIRMWARE_QUEUE_MAX_AGE", 86400) // 3600)))


def process_firmware_updates(devices):
    """Run update jobs for the given devices now and wait for them (kept for callers that
    need a synchronous batch; the scheduler is the normal path)."""
    if not devices:
        return
    workers = get_dynamic_firmware_workers(len(devices))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(FirmwareScheduler._work_job, dev.id, "work"): dev for dev in devices}
        _wait_with_progress(futures, "Firmware update")


def process_routerboot_upgrades(devices):
    if not devices:
        return
    workers = get_dynamic_firmware_workers(len(devices))

    def _routerboot_worker(dev):
        try:
            firm_lib.upgrade_routerboot(dev)
        finally:
            database.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_routerboot_worker, dev): dev for dev in devices}
        _wait_with_progress(futures, "RouterBOOT upgrade")


def updater():
    """One scheduling pass (compatibility entry point)."""
    scheduler = FirmwareScheduler()
    try:
        return scheduler.tick()
    finally:
        scheduler.work_pool.shutdown(wait=True)
        scheduler.verify_pool.shutdown(wait=True)


def _reset_service_flag():
    """The firmware mule is the only owner of signal 150: a flag left set by a previous
    process (killed while working) must not block the scheduler forever."""
    try:
        with database.connection_context():
            task = db_tasks.firmware_service_status()
            if task.status:
                log.warning("Firmware service flag was left set by a previous run - reset")
                task.status = 0
                task.save()
    except Exception as e:
        log.warning(f"Could not reset firmware service flag: {e}")


def main():
    tune_process_db_pool(role="firmware")
    _reset_service_flag()
    scheduler = FirmwareScheduler()
    log.info(f"Firmware scheduler started ({scheduler.work_workers} update workers, {VERIFY_WORKERS} verify workers)")
    while True:
        try:
            scheduler.tick()
            # daily history / file cleanup, in its own thread (never delays the scheduler)
            retention.maybe_start()
            # one-time cleanup of secrets in old System Log rows (own thread, never raises)
            audit_redact_backfill.maybe_start()
        except KeyboardInterrupt:
            log.info("Firmware updater interrupted by user")
            break
        except Exception as e:
            log.error(f"Firmware scheduler error: {e}")
        finally:
            database.close()
        time.sleep(TICK_SECONDS)


if __name__ == '__main__':
    main()
