#!/usr/bin/python
# -*- coding: utf-8 -*-

# data_grabber.py: independent worker process for grabbing data of devices
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from libs import util
import config
from libs.db import db_device, db_sysconfig, db_events
from libs.db.db import database
from libs.red import RedisDB
import netifaces
import json
import queue
import logging

log = logging.getLogger("Data_grabber")

# --- Tuning constants ---
# Small deployments (< 200 devices): defaults below are fine.
# Enterprise (500+ devices): increase MAX_WORKERS to 50, BATCH_SIZE to 200.
MAX_WORKERS = getattr(config, "DATAGRABBER_CONCURRENCY", 25)
                   # Enterprise: 50
BATCH_SIZE = 100   # Devices processed per ThreadPoolExecutor batch
                   # Enterprise: 200
MIN_INTERVAL = 30  # Minimum seconds to rest between grab cycles
DEFAULT_INTERVAL = 60  # Target interval in seconds



_grab_running = False  # Overlap guard — prevents concurrent grab cycles

def grab_device_data(timer=2):
    global _grab_running
    if _grab_running:
        log.warning("Previous grab cycle still running, skipping this round")
        return
    _grab_running = True
    try:
        all_devices = [d for d in list(db_device.get_all_device())
                       if not hasattr(d, 'device_type') or not d.device_type or d.device_type == 'mikrotik']
        num_devices = len(all_devices)
        q = queue.Queue()
        if os.getenv("DEV_MODE") == "true":
            log.info(f"Data grabber started for {num_devices} devices")

        def thread_worker(dev, q_obj):
            """Each worker opens and closes its own DB connection cleanly."""
            with database.connection_context():
                util.grab_device_data(dev, q_obj)

        # Process in batches to control memory pressure at scale
        for batch_start in range(0, num_devices, BATCH_SIZE):
            batch = all_devices[batch_start:batch_start + BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(thread_worker, dev, q): dev for dev in batch}
                for future in as_completed(futures):
                    try:
                        future.result(timeout=120)  # 2-min timeout per device
                    except Exception as e:
                        dev = futures[future]
                        log.error(f"Poller failure for device {dev.id} ({dev.ip}): {e}")

        # Process results queue
        res = []
        totals = {'rx-total': 0, 'tx-total': 0}
        has_data = False
        while not q.empty():
            qres = q.get_nowait()
            if not qres.get("reason", False):
                data = qres.get("data", None)
                if data:
                    rx_val = data.get("rx-total")
                    if rx_val is not None:
                        totals['rx-total'] += rx_val
                        has_data = True
                    tx_val = data.get("tx-total")
                    if tx_val is not None:
                        totals['tx-total'] += tx_val
                        has_data = True
                res.append(qres)
            else:
                db_events.connection_event(
                    qres['id'], 'Data Puller',
                    qres.get("detail", "connection"), "Critical", 0,
                    qres.get("reason", "problem in data puller")
                )

        keys = ["rx-total", "tx-total"]
        redopts = {"dev_id": 'all', "keys": keys}
        try:
            if has_data:
                reddb = RedisDB(redopts)
                reddb.dev_create_keys()
                reddb.add_dev_data(totals)
        except Exception as e:
            log.error(e)
    finally:
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

        # Adaptive sleep: rest for at least MIN_INTERVAL seconds total,
        # but if cycle took longer than DEFAULT_INTERVAL just rest MIN_INTERVAL.
        sleep_time = max(MIN_INTERVAL, DEFAULT_INTERVAL - elapsed)
        if os.getenv("DEV_MODE") == "true":
            log.info(f"Data grab cycle completed in {elapsed:.1f}s, sleeping {sleep_time:.1f}s")
        time.sleep(sleep_time)

    
if __name__ == '__main__':
    main()
