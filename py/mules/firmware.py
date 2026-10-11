#!/usr/bin/python
# -*- coding: utf-8 -*-

# firmware.py: independent worker process for updating firmware of incomplete update tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
import concurrent.futures
from libs import util, firm_lib
from libs.db import db_tasks, db_device, db_sysconfig
from libs.db.db import database, tune_process_db_pool
import config
import logging
import queue
import os

log = logging.getLogger("Firmware")

try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False

def get_dynamic_firmware_workers(num_devices):
    """
    Scale concurrent firmware uploads dynamically based on device count.
    Firmware packages are 15-35MB each; excessive parallel uploads choke WAN bandwidth
    and exhaust DB connections.
    """
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

FIRMWARE_PROGRESS_LOG_SECONDS = 300


def _wait_with_progress(futures, label):
    """Wait for ALL firmware jobs to finish - deliberately without a deadline, because
    abandoning a router mid-upgrade is worse than a slow batch. Every few minutes the
    devices still in progress are logged, and worker exceptions are logged (they were
    silently dropped before)."""
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


def process_firmware_updates(devices):
    """Process firmware updates using a bounded thread pool (no time limit: an upgrade in
    progress is never abandoned; progress is logged instead)."""
    if not devices:
        return
    
    tune_process_db_pool(role="firmware", num_devices=len(devices))
    workers = get_dynamic_firmware_workers(len(devices))
    
    def _firmware_worker(dev):
        try:
            q = queue.Queue()
            if ISPRO:
                utilpro.update_device(dev, {"version_to_install": dev.firmware_to_install}, False, q)
            else:
                firm_lib.update_device(dev, q)
        finally:
            database.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_firmware_worker, dev): dev for dev in devices}
        _wait_with_progress(futures, "Firmware update")

def process_routerboot_upgrades(devices):
    """Process RouterBOOT upgrades using a bounded thread pool (no time limit, progress logged)."""
    if not devices:
        return
    
    tune_process_db_pool(role="firmware", num_devices=len(devices))
    workers = get_dynamic_firmware_workers(len(devices))

    def _routerboot_worker(dev):
        try:
            q = queue.Queue()
            firm_lib.upgrade_routerboot(dev, q)
        finally:
            database.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_routerboot_worker, dev): dev for dev in devices}
        _wait_with_progress(futures, "RouterBOOT upgrade")

def updater():
    task = db_tasks.firmware_service_status()
    if task.status:
        return False

    # Prevent collision with active background update jobs initiated via bgtasks
    try:
        update_job = db_tasks.update_job_status()
        if update_job and update_job.status:
            return False
    except Exception:
        pass

    if os.getenv("DEV_MODE") == "true":
        log.info("Firmware updater started")
    task.status = 1
    task.save()
    try:
        # Read configurable retry policy
        max_retries = 2
        try:
            ret_cfg = db_sysconfig.get_sysconfig('firmware_max_retries')
            if ret_cfg:
                max_retries = int(ret_cfg)
        except Exception:
            pass

        auto_retry = True
        try:
            auto_retry = (db_sysconfig.get_sysconfig('firmware_auto_retry') != 'False')
        except Exception:
            pass

        # Phase 1: Verify devices pending post-reboot verification
        # Devices that have received packages and rebooted, but need live version confirmation
        pending_verif = list(db_device.Devices.select().where(
            db_device.Devices.firmware_to_install.is_null(False) &
            ((db_device.Devices.status == 'updated') | (db_device.Devices.status == 'rebooting'))
        ))
        for pdev in pending_verif:
            try:
                firm_lib.verify_device_firmware(pdev)
            except Exception as pe:
                log.warning(f"Verification error on {pdev.name}: {pe}")

        # Phase 2: Process firmware update retries for genuinely failed devices (never updating/rebooting)
        if auto_retry:
            devs_retry = list(db_device.Devices.select().where(
                db_device.Devices.firmware_to_install.is_null(False) & 
                (db_device.Devices.failed_attempt < max_retries) &
                (db_device.Devices.status == 'failed')
            ))
            if devs_retry:
                devs_retry = [d for d in devs_retry if util.check_port(d.ip, util.get_device_port(d))]
                if devs_retry:
                    log.info(f"Processing firmware updates for {len(devs_retry)} devices (max retries: {max_retries})")
                    process_firmware_updates(devs_retry)
        
        # Phase 3: Process RouterBOOT upgrades (exclude devices actively updating or rebooting)
        devs_upgrade = list(db_device.Devices.select().where(
            (db_device.Devices.failed_attempt < max_retries) & 
            (db_device.Devices.upgrade_device == True) &
            (db_device.Devices.status != 'updating') &
            (db_device.Devices.status != 'rebooting')
        ))
        
        if devs_upgrade:
            devs_upgrade = [d for d in devs_upgrade if util.check_port(d.ip, util.get_device_port(d))]
            if devs_upgrade:
                log.info(f"Processing RouterBOOT upgrades for {len(devs_upgrade)} devices")
                process_routerboot_upgrades(devs_upgrade)
            
    except Exception as e:
        log.error(f"Firmware updater error: {e}")
        return False
    finally:
        task.status = 0
        task.save()
        database.close()
    return False

def main():
    while True:
        try:
            updater()
        except KeyboardInterrupt:
            log.info("Firmware updater interrupted by user")
            break
        except Exception as e:
            log.error(f"Firmware updater main loop error: {e}")
        time.sleep(60)

if __name__ == '__main__':
    main()

