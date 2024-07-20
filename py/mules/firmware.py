#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process for updating firmware of incomplate update tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
from libs import util
from libs.db import db_tasks,db_device
import logging
import queue
from threading import Thread
log = logging.getLogger("Firmware")
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

def updater():
    task=db_tasks.firmware_service_status()
    if not task.status:
        log.info("Firmware updater started")
        task.status=1
        task.save()
        try:
            devs = list(db_device.Devices.select().where(db_device.Devices.firmware_to_install.is_null(False) & (db_device.Devices.failed_attempt < 4) & ((db_device.Devices.status=='updated' ) | ( db_device.Devices.status=='failed'))))
            num_threads = len(devs)
            q = queue.Queue()
            threads = []
            for dev in devs:
                if ISPRO:
                    t = Thread(target=utilpro.update_device, args=(dev,{"version_to_install":dev.firmware_to_install},False, q))
                else:
                    t = Thread(target=util.update_device, args=(dev, q))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            res=[]
            for _ in range(num_threads):
                qres=q.get()
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False

def main():
    while True:
        try:
            updater()
        except:
            pass
        time.sleep(60)

if __name__ == '__main__':
    main()

