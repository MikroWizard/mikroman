#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process for grabbing data of devices
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
from libs import util
from libs.db import db_device,db_sysconfig,db_events
from threading import Thread
from libs.red import RedisDB
import netifaces
import json
import queue

import logging


log = logging.getLogger("Data_grabber")



def grab_device_data(timer=2):
    all_devices=list(db_device.get_all_device())
    num_threads = len(all_devices)
    q = queue.Queue()
    threads = []
    log.info("Data grabber started")
    for dev in all_devices:
        time.sleep(0.2)
        t = Thread(target=util.grab_device_data, args=(dev, q))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    res=[]
    totals={
     'rx-total':0,
     'tx-total':0
    }
    data=False
    for _ in range(num_threads):
        qres=q.get()
        if not qres.get("reason",False):
            data=qres.get("data", None)
            if data:
                if data.get("rx-total", False):
                    totals['rx-total']+=data["rx-total"]
                if data.get("tx-total", False):
                    totals["tx-total"]+=data["tx-total"]
            res.append(qres)
        else:
            db_events.connection_event(qres['id'],'Data Puller',qres.get("detail","connection"),"Critical",0,qres.get("reason","problem in data puller"))
    keys=["rx-total","tx-total"]
    redopts={
            "dev_id":'all',
            "keys":keys
    }
    try:
        if data:
            reddb=RedisDB(redopts)
            reddb.dev_create_keys()
            reddb.add_dev_data(data)
    except Exception as e:
        log.error(e)

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


def main():
    while True:
        config=db_sysconfig.get_scan_mode().value
        get_all_ipv4_addresses()
        grab_device_data()      
        time.sleep(60)
        log.info("data grabbing end")

    
if __name__ == '__main__':
    main()

