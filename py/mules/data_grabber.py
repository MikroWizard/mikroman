#!/usr/bin/python
# -*- coding: utf-8 -*-

# data_grabber.py: independent worker process for grabbing data of devices
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import math
import time
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from libs import util
import config
from libs.db import db_device, db_sysconfig, db_events
from libs.db.db import database, tune_process_db_pool, get_db_stats, reset_db_stats
from libs.red import RedisDB
import netifaces
import json
import queue
import logging

try:
    import uwsgi
except ImportError:
    uwsgi = None

log = logging.getLogger("Data_grabber")

# --- Tuning constants ---
MIN_INTERVAL = 30  # Minimum seconds to rest between grab cycles
ALIGNED_MIN_REST = 5  # multi-mule: minimum rest before the next aligned cycle start
DEFAULT_INTERVAL = 60  # Target interval in seconds

def get_dynamic_worker_count(num_devices):
    """
    Dynamically scale worker concurrency based on device count and database limits.
    Ensures optimal throughput so 1000-1500 devices finish within 30-40 seconds,
    while smaller fleets run swiftly without overloading server resources.
    """
    configured = getattr(config, "DATAGRABBER_CONCURRENCY", None)
    if configured and configured > 0:
        base_workers = configured
    else:
        base_workers = 25

    if num_devices <= 0:
        return 1
    elif num_devices <= 30:
        # Micro tier: fast, lightweight
        return min(num_devices, 15)
    elif num_devices <= 150:
        # Small customer (up to ~150-200 devices):
        # 20-25 workers finish 100 devices in ~4-6 seconds.
        # Safely within default PostgreSQL 100 max_connections.
        return min(num_devices, max(base_workers, 20))
    elif num_devices <= 500:
        # Medium customer (150-500 devices):
        # 35-40 workers finish in 12-18 seconds.
        return min(num_devices, max(base_workers, 40))
    elif num_devices <= 1000:
        # Large customer (500-1000 devices):
        # 60-75 workers finish in 20-30 seconds.
        return min(num_devices, max(base_workers, 75))
    else:
        # Enterprise & Hyperscale (1,000 to 1,500+ devices):
        # 100-120 continuous workers finish 1500 devices in ~35-45 seconds even over WAN/VPN links.
        return min(num_devices, max(base_workers, 120))


def get_poller_shard_config():
    """
    Detect whether this process is running as a partitioned/sharded poller.
    Returns (shard_index, total_shards).
    - If total_shards == 1: process all devices.
    - If total_shards == 2: shard 0 processes even IDs (id % 2 == 0), shard 1 processes odd IDs (id % 2 == 1).
    """
    # 1. Environment variable override (CLI or custom wrapper)
    env_shard = os.getenv("DATAGRABBER_SHARD_INDEX")
    env_total = os.getenv("DATAGRABBER_TOTAL_SHARDS")
    if env_shard is not None and env_total is not None:
        try:
            return int(env_shard), max(1, int(env_total))
        except ValueError:
            pass

    # 2. uWSGI mule ID detection against PYSRV_DATAGRABBER_MULES
    mule_id = 0
    if uwsgi is not None:
        try:
            mule_val = getattr(uwsgi, "mule_id", 0)
            mule_id = mule_val() if callable(mule_val) else int(mule_val or 0)
        except Exception as e:
            log.warning("Could not obtain uwsgi mule_id: %s", e)
            mule_id = 0

    if mule_id > 0:
        cfg_mules = getattr(config, "DATAGRABBER_MULES", "")
        if cfg_mules:
            try:
                if isinstance(cfg_mules, str):
                    mule_list = [int(x.strip()) for x in cfg_mules.split(",") if x.strip().isdigit()]
                elif isinstance(cfg_mules, (list, tuple)):
                    mule_list = [int(x) for x in cfg_mules]
                else:
                    mule_list = []

                if mule_id in mule_list:
                    return mule_list.index(mule_id), len(mule_list)
            except Exception as e:
                log.warning("Could not parse DATAGRABBER_MULES: %s", e)

    # 3. Default: single mule, process all devices
    return 0, 1

_grab_running = False  # Overlap guard — prevents concurrent grab cycles

# Hard ceiling for one poll cycle (seconds). Router I/O has a 5s socket timeout, so this
# only triggers on a genuinely hung device thread.
CYCLE_DEADLINE = int(getattr(config, "DATAGRABBER_CYCLE_DEADLINE", 240) or 240)

SHARD_TOTALS_KEY = "poller_shard_totals::{}"
SHARD_TOTALS_TTL = 180
# Fleet total = sum of every device's rx/tx bps and pps (dashboard "total traffic", sensor::all).
FLEET_TOTAL_KEYS = ("rx-total", "tx-total", "rxp-total", "txp-total")
# A shard missing for fewer cycles than this is assumed to be still finishing its first
# cycle (start-up race): the fleet total is skipped instead of published half-empty.
MISSING_SHARD_PUBLISH_AFTER = 3
# Shard 0 waits up to this long for the other shards' totals of the SAME cycle (all poller
# mules start together and run on the same 60 s rhythm, so they usually finish within seconds
# of each other). Without the wait the fleet total mixed this cycle with the previous one.
SHARD_WAIT_SECONDS = 15
# Another shard's totals belong to the same cycle when its cycle started within this window
# of shard 0's cycle start. Mules start together and cycles are at least MIN_INTERVAL (30 s)
# apart, so the previous cycle of another shard is always older than this.
SAME_CYCLE_WINDOW = 20
_missing_shard_cycles = {}
_fleet_keys_created = False


def empty_fleet_totals():
    return {k: 0 for k in FLEET_TOTAL_KEYS}


# Each shard keeps the totals of its last few cycles: a shard that is a cycle AHEAD of shard 0
# (shard 0 had a long cycle) must not have overwritten the cycle shard 0 is summing.
SHARD_HISTORY = 4


def _read_shard(r, s):
    """List of {cycle, rx-total, ...} payloads of shard s, oldest first (or [])."""
    try:
        raw = r.get(SHARD_TOTALS_KEY.format(s))
        data = json.loads(raw) if raw else []
    except Exception:
        return []
    if isinstance(data, dict):          # single payload (older format)
        data = [data]
    return [d for d in data if isinstance(d, dict)]


def _store_shard(r, s, payload):
    history = [d for d in _read_shard(r, s) if d.get("cycle") != payload.get("cycle")]
    history = (history + [payload])[-SHARD_HISTORY:]
    r.setex(SHARD_TOTALS_KEY.format(s), SHARD_TOTALS_TTL, json.dumps(history))


def _pick_cycle(entries, cycle_start):
    """The entry of the same cycle as cycle_start (closest start within SAME_CYCLE_WINDOW),
    else None. Entries without a cycle stamp count as matching (older format)."""
    if not entries:
        return None
    if cycle_start is None:
        return entries[-1]
    best = None
    for d in entries:
        c = d.get("cycle")
        if c is None:
            return d
        delta = abs(c - cycle_start)
        if delta <= SAME_CYCLE_WINDOW and (best is None or delta < best[0]):
            best = (delta, d)
    return best[1] if best else None


def combine_shard_totals(r, shard_idx, total_shards, totals, cycle_start=None,
                         wait_seconds=SHARD_WAIT_SECONDS, sleep=time.sleep, clock=time.time):
    """Multi-mule fleet total.

    Every shard stores the totals of its last SHARD_HISTORY cycles with their cycle start.
    Only shard 0 publishes the combined fleet total (one writer -> one point per cycle in
    sensor::all::*). It waits up to `wait_seconds` until every live shard has stored the totals
    of the same cycle (start within SAME_CYCLE_WINDOW of its own), so the fleet total is the
    exact sum of all devices polled in this cycle - also when another shard is already a cycle
    ahead. A shard that is late contributes its latest totals.

    While another shard has never reported (start-up) the point is skipped: a partial sum
    would show as a false dip in the fleet traffic chart. A shard missing for
    MISSING_SHARD_PUBLISH_AFTER cycles is treated as dead: an error is logged (its devices are
    NOT polled - PYSRV_DATAGRABBER_MULES lists a mule uwsgi.ini does not start), shard 0 stops
    waiting for it and publishes the partial total.

    Returns (publish, totals_to_publish).
    """
    if total_shards <= 1:
        return True, totals
    try:
        _store_shard(r, shard_idx, dict(totals, cycle=cycle_start))
    except Exception as e:
        log.warning("Could not store shard totals: %s", e)
    if shard_idx != 0:
        return False, totals

    deadline = clock() + max(0, wait_seconds or 0)
    while True:
        history = {s: _read_shard(r, s) for s in range(total_shards)}
        snap = {s: _pick_cycle(history[s], cycle_start) for s in range(total_shards)}
        snap[shard_idx] = dict(totals, cycle=cycle_start)
        pending = [s for s in range(total_shards)
                   if snap[s] is None and _missing_shard_cycles.get(s, 0) < MISSING_SHARD_PUBLISH_AFTER]
        if not pending or clock() >= deadline:
            break
        sleep(0.25)
    for s in range(total_shards):
        if snap[s] is None and history[s]:
            snap[s] = history[s][-1]        # late shard: its latest cycle

    combined = empty_fleet_totals()
    waiting = False
    for s in range(total_shards):
        data = snap[s]
        if data is None:
            _missing_shard_cycles[s] = _missing_shard_cycles.get(s, 0) + 1
            if _missing_shard_cycles[s] >= MISSING_SHARD_PUBLISH_AFTER:
                log.error(f"Poller shard {s} has not reported for {_missing_shard_cycles[s]} cycles. "
                          f"Devices with id % {total_shards} == {s} are NOT being polled. "
                          f"Check PYSRV_DATAGRABBER_MULES matches the data_grabber mules in uwsgi.ini.")
            else:
                waiting = True
            continue
        _missing_shard_cycles[s] = 0
        for k in FLEET_TOTAL_KEYS:
            try:
                combined[k] += data.get(k, 0) or 0
            except Exception:
                pass
    if waiting:
        return False, combined
    return True, combined

def grab_device_data(timer=2):
    global _grab_running, _fleet_keys_created
    if _grab_running:
        log.warning("Previous grab cycle still running, skipping this round")
        return
    _grab_running = True
    cycle_start = time.time()
    try:
        shard_idx, total_shards = get_poller_shard_config()
        all_devices = [d for d in list(db_device.get_all_device())
                       if not hasattr(d, 'device_type') or not d.device_type or d.device_type == 'mikrotik']

        if total_shards > 1:
            all_devices = [d for d in all_devices if (d.id % total_shards) == shard_idx]

        num_devices = len(all_devices)
        tune_process_db_pool(role="poller", num_devices=num_devices)
        q = queue.Queue()
        if os.getenv("DEV_MODE") == "true" or num_devices >= 100:
            shard_info = f" [Shard {shard_idx + 1}/{total_shards} - IDs where id % {total_shards} == {shard_idx}]" if total_shards > 1 else ""
            log.info(f"Data grabber started for {num_devices} devices{shard_info}")

        # Pre-fetch all active 'Data Puller' events in ONE query before spawning threads.
        # This completely eliminates thread startup burst and N-query pool collisions.
        events_map = {}
        try:
            with database.connection_context():
                active_events = list(db_events.Events.select().where(
                    db_events.Events.src == "Data Puller",
                    db_events.Events.status == 0
                ).dicts())
                for ev in active_events:
                    dev_id = ev.get('devid')
                    if dev_id:
                        events_map.setdefault(dev_id, []).append(ev)
        except Exception as e:
            log.warning("Could not pre-fetch poller events: %s", e)

        # Pre-fetch static sysconfig flags once per cycle to prevent N-query amplification
        try:
            sysconfig_flags = {
                'force_syslog': db_sysconfig.get_sysconfig('force_syslog') == "True",
                'force_radius': db_sysconfig.get_sysconfig('force_radius') == "True",
                'rad_secret': db_sysconfig.get_sysconfig('rad_secret') or "",
                'old_firmware_action': db_sysconfig.get_sysconfig('old_firmware_action') or "keep",
                'old_version': db_sysconfig.get_sysconfig('old_version'),
                'latest_version': db_sysconfig.get_sysconfig('latest_version'),
            }
        except Exception as e:
            log.warning("Could not pre-fetch sysconfig flags: %s", e)
            sysconfig_flags = None

        def thread_worker(dev, q_obj):
            try:
                util.grab_device_data(dev, q_obj, sysconfig_flags=sysconfig_flags, events_map=events_map)
            finally:
                try:
                    database.close()
                except Exception:
                    pass

        worker_count = get_dynamic_worker_count(num_devices)
        if os.getenv("DEV_MODE") == "true" or num_devices >= 100:
            log.info(f"Polling {num_devices} devices with {worker_count} concurrent workers")

        # Continuous ThreadPool execution:
        # All devices are submitted to a single continuous pool. Workers pull the next
        # device as soon as they finish one, ensuring maximum pipeline throughput.
        # A whole-cycle deadline keeps the mule alive even if a device thread hangs
        # (threads cannot be killed; a hung thread is abandoned and reported).
        executor = ThreadPoolExecutor(max_workers=worker_count)
        futures = {executor.submit(thread_worker, dev, q): dev for dev in all_devices}
        done, not_done = wait(futures, timeout=CYCLE_DEADLINE)
        for future in done:
            dev = futures[future]
            try:
                future.result()
            except Exception as e:
                log.error(f"Poller failure for device {dev.id} ({dev.ip}): {e}")
        if not_done:
            stuck = [futures[f] for f in not_done]
            log.error(f"Poll cycle deadline ({CYCLE_DEADLINE}s) reached: {len(stuck)} device(s) not finished, "
                      f"abandoning them this cycle: {[d.ip for d in stuck[:20]]}")
        executor.shutdown(wait=False, cancel_futures=True)

        # Process results queue
        res = []
        totals = empty_fleet_totals()
        has_data = False
        with database.connection_context():
            while not q.empty():
                qres = q.get_nowait()
                if not qres.get("reason", False):
                    data = qres.get("data", None)
                    if data:
                        for k in FLEET_TOTAL_KEYS:
                            val = data.get(k)
                            if val is not None:
                                totals[k] += val
                                has_data = True
                    res.append(qres)
                else:
                    dev_obj = db_device.get_device(qres['id'])
                    dev_status = dev_obj.get('status') if dev_obj else ''
                    if dev_status in ['updating', 'rebooting']:
                        log.info(f"Device {qres['id']} is currently {dev_status} (rebooting to apply update). Skipping unreachable alert.")
                    else:
                        db_events.connection_event(
                            qres['id'], 'Data Puller',
                            qres.get("detail", "connection"), "Critical", 0,
                            qres.get("reason", "problem in data puller")
                        )

        redopts = {"dev_id": 'all', "keys": list(FLEET_TOTAL_KEYS)}
        try:
            if has_data or total_shards > 1:
                reddb = RedisDB(redopts)
                publish, totals = combine_shard_totals(reddb.r, shard_idx, total_shards, totals,
                                                       cycle_start=cycle_start)
                if publish:
                    if not _fleet_keys_created:
                        # once per process (keys + compaction rules); add_dev_data re-creates
                        # a key that disappeared
                        reddb.dev_create_keys()
                        _fleet_keys_created = True
                    reddb.add_dev_data(totals)
        except Exception as e:
            log.error(e)
    finally:
        if os.getenv("DEV_MODE") == "true":
            stats = get_db_stats()
            log.info(
                "[DEV_MODE CYCLE DB SUMMARY] Total queries: %s (SELECT: %s, UPDATE: %s, INSERT: %s, DELETE: %s)",
                stats.get("total", 0), stats.get("select", 0), stats.get("update", 0), stats.get("insert", 0), stats.get("delete", 0)
            )
            reset_db_stats()
        _grab_running = False

def get_all_ipv4_addresses():
    ips=db_sysconfig.get_sysconfig('all_ip')
    ipv4_addresses = []
    
    # Iterate over all network interfaces
    for interface in netifaces.interfaces():
        # Get all IPv4 addresses associated with the interface
        addresses = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
        
        # Append IPv4 addresses to the list
        for link in addresses:
            if '127.0.0.1' in link['addr']:
                continue
            ipv4_addresses.append(link['addr'])
    ipv4_addresses.sort()
    ipv4_addresses=json.dumps(ipv4_addresses)
    if ips!=ipv4_addresses:
        db_sysconfig.update_sysconfig('all_ip',ipv4_addresses)


def _handle_shutdown(signum, frame):
    """Force-exit the mule on SIGTERM/SIGINT during uWSGI reload.

    IMPORTANT: Only async-signal-safe functions allowed here.
    """
    os.write(2, b"[Data_grabber] Received shutdown signal, forcing mule exit\n")
    os._exit(0)


def next_sleep(elapsed, now, total_shards, interval=None):
    """Seconds to sleep before the next cycle.

    One mule: rest at least MIN_INTERVAL, cycle every DEFAULT_INTERVAL when it is fast enough.
    Several mules: start every cycle on the same wall-clock boundary (multiple of the interval)
    in all mules, so their cycles stay in step even when cycle lengths differ. Shard 0 then sums
    the same cycle of every shard for the fleet total instead of mixing cycles after drift.
    """
    interval = interval or DEFAULT_INTERVAL
    if total_shards <= 1:
        return max(MIN_INTERVAL, interval - elapsed)
    next_start = (math.floor((now + ALIGNED_MIN_REST) / interval) + 1) * interval
    return next_start - now


def main():
    # uWSGI may block SIGTERM/SIGINT in the mule's signal mask via
    # sigprocmask() before running this script. Explicitly unblock them
    # and (re)install our handler AFTER uWSGI's initialization is complete.
    try:
        signal.pthread_sigmask(
            signal.SIG_UNBLOCK,
            {signal.SIGTERM, signal.SIGINT}
        )
    except (AttributeError, OSError):
        # pthread_sigmask not available on all platforms
        pass
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    while True:
        config = db_sysconfig.get_scan_mode().value
        get_all_ipv4_addresses()

        start_time = time.time()
        grab_device_data()
        elapsed = time.time() - start_time

        # One mule: adaptive sleep (rest >= MIN_INTERVAL). Several: aligned cycle starts.
        sleep_time = next_sleep(elapsed, time.time(), get_poller_shard_config()[1])
        if os.getenv("DEV_MODE") == "true":
            log.info(f"Data grab cycle completed in {elapsed:.1f}s, sleeping {sleep_time:.1f}s")
        time.sleep(sleep_time)

    
if __name__ == '__main__':
    main()
