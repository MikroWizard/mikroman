#!/usr/bin/python
# -*- coding: utf-8 -*-

# firmware.py: independent worker process for updating firmware of incomplete update tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
import concurrent.futures
from libs import util, firm_lib
from libs.db import db_tasks, db_device, db_sysconfig
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

# Configuration
MAX_CONCURRENT_THREADS = getattr(config, "FIRMWARE_CONCURRENCY", 40)

def process_firmware_updates(devices):
    """Process firmware updates using thread pool"""
    if not devices:
        return
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_THREADS) as executor:
        futures = []
        for dev in devices:
            q = queue.Queue()
            if ISPRO:
                future = executor.submit(utilpro.update_device, dev, {"version_to_install": dev.firmware_to_install}, False, q)
            else:
                future = executor.submit(firm_lib.update_device, dev, q)
            futures.append(future)
        
        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

def process_routerboot_upgrades(devices):
    """Process RouterBOOT upgrades using thread pool"""
    if not devices:
        return
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_THREADS) as executor:
        futures = []
        for dev in devices:
            q = queue.Queue()
            future = executor.submit(firm_lib.upgrade_routerboot, dev, q)
            futures.append(future)
        
        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

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

