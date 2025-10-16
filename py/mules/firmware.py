#!/usr/bin/python
# -*- coding: utf-8 -*-

# firmware.py: independent worker process for updating firmware of incomplete update tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
import concurrent.futures
from libs import util, firm_lib
from libs.db import db_tasks, db_device
import logging
import queue

log = logging.getLogger("Firmware")

try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False

# Configuration
MAX_CONCURRENT_THREADS = 40

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
    if not task.status:
        log.info("Firmware updater started")
        task.status = 1
        task.save()
        try:
            # Process firmware updates
            devs = list(db_device.Devices.select().where(
                db_device.Devices.firmware_to_install.is_null(False) & 
                (db_device.Devices.failed_attempt < 4) &
                ((db_device.Devices.status == 'updated') | (db_device.Devices.status == 'failed'))
            ))
            
            if devs:
                log.info(f"Processing firmware updates for {len(devs)} devices")
                process_firmware_updates(devs)
            
            # Process RouterBOOT upgrades
            devs_upgrade = list(db_device.Devices.select().where(
                (db_device.Devices.failed_attempt < 4) & 
                (db_device.Devices.upgrade_device == True)
            ))
            
            if devs_upgrade:
                log.info(f"Processing RouterBOOT upgrades for {len(devs_upgrade)} devices")
                process_routerboot_upgrades(devs_upgrade)
                
        except Exception as e:
            log.error(f"Firmware updater error: {e}")
            task.status = 0
            task.save()
            return False
    
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

