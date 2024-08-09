#!/usr/bin/python
# -*- coding: utf-8 -*-

# bgtasks.py: background tasks, which are run in separate worker processes
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi

from uwsgidecorators import spool
from playhouse.shortcuts import model_to_dict
from libs import util
import time
from libs.db import db_tasks,db_device,db_events,db_user_group_perm,db_device
from threading import Thread
import queue
import pexpect
import re
from libs.db.db_device import Devices,EXCLUDED,database
import ipaddress
import socket
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from typing import Dict 
import json
import datetime

sensor_pile = queue.LifoQueue()
other_sensor_pile = queue.LifoQueue()

import logging
log = logging.getLogger("bgtasks")

def serialize_datetime(obj): 
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 

@spool(pass_arguments=True)
def check_devices_for_update(*args, **kwargs):
    task=db_tasks.update_check_status()
    if not task.status:
        task.status=1
        task.save()
        try:
            #check only one device for update
            if kwargs.get('devices',False):
                devids=kwargs.get('devices',False)
                uid=kwargs.get('uid',False)
                devs=False
                if "0" == devids:
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
                else:
                    devids=devids.split(",")
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid,devids))
                num_threads = len(devs)
                q = queue.Queue()
                threads = []
                for dev in devs:
                    t = Thread(target=util.check_device_firmware_update, args=(dev, q))
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join()
                res=[]
                for _ in range(num_threads):
                    qres=q.get()
                    if not qres.get("reason",False):
                        res.append(qres)
                    else:
                        db_events.connection_event(dev.id,qres["reason"])
                db_device.update_devices_firmware_status(res)
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False


@spool(pass_arguments=True)
def update_device(*args, **kwargs):
    task=db_tasks.update_job_status()
    if not task.status:
        task.status=1
        task.save()
        try:
            if kwargs.get('devices',False):
                devids=kwargs.get('devices',False)
                devs=False
                uid=kwargs.get('uid',False)
                if "0" == devids:
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
                else:
                    devids=devids.split(",")
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid,devids))
                num_threads = len(devs)
                q = queue.Queue()
                threads = []
                for dev in devs:
                    if dev.failed_attempt>0:
                        dev.failed_attempt=0
                        dev.save()
                    if(not dev.update_availble):
                        continue
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

@spool(pass_arguments=True)
def download_firmware(*args, **kwargs):
    task=db_tasks.downloader_job_status()
    if not task.status:
        task.status=1
        task.save()
        # time.sleep(5)
        try:
            if kwargs.get('version',False):
                ver=kwargs.get('version',False)
                num_threads = 1
                q = queue.Queue()
                threads = []
                t = Thread(target=util.download_firmware_to_repository, args=(ver, q))
                t.start()
                threads.append(t)
                for t in threads:
                    t.join()
                res=[]
                for _ in range(num_threads):
                    qres=q.get()
                print(qres)
                # db_device.update_devices_firmware_status(res)
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False

@spool(pass_arguments=True)
def backup_devices(*args, **kwargs):
    task=db_tasks.backup_job_status()
    if not task.status:
        task.status=1
        task.save()
        # time.sleep(5)
        try:
            if kwargs.get('devices',False):
                devices=kwargs.get('devices',False)
                if len(devices):
                    num_threads = len(devices)
                    q = queue.Queue()
                    threads = []
                    for dev in devices:
                        t = Thread(target=util.backup_routers, args=(dev, q))
                        t.start()
                        threads.append(t)
                    for t in threads:
                        t.join()
                    res=[]
                    for _ in range(num_threads):
                        qres=q.get()
                        if not qres['status']:
                            util.log_alert('backup',dev,'Backup failed')
                        res.append(qres)
                else:
                    task.status=0
                    task.save()
                    return False
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False

def extract_device_from_macdiscovery(line):
    regex = r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*?([0-9A-Fa-f]{1,2}:[0-9A-Fa-f]{1,3}:[0-9A-Fa-f]{1,3}:[0-9A-Fa-f]{1,3}:[0-9A-Fa-f]{1,3}:[0-9A-Fa-f]{1,3})\s+(.+?(?= \(M))\s+(\(.+\))\s+up (\d{1,5} days \d{1,5} hours)\s+?([A-Za-z0-9]{1,9}-?[A-Za-z0-9]{1,9})\s+?([a-z]{1,7}[0-9]{0,2}/?[a-z]{1,7}[0-9]{0,2})"

    matches = re.finditer(regex, line, re.MULTILINE)
    sgroups=[]   
    for matchNum, match in enumerate(matches, start=1):
        for groupNum in range(0, len(match.groups())):
            groupNum = groupNum + 1
            sgroups.append(match.group(groupNum))
    return sgroups

@spool(pass_arguments=True)
def scan_with_mac(timer=2):
    task=db_tasks.backup_job_status()
    child = pexpect.spawn('mactelnet -l')
    child.expect("MAC-Address")
    output=""

    while child.isalive() and timer!=0:
        time.sleep(1)
        # print("loging")
        #output=child.read_nonblocking(131)
        try:
            temp=child.read_nonblocking(131,1).decode()
        except:
            temp=output
        if not temp in output:
            output+=temp
        timer-=1
    lines=output.split("\r\n")
    data=[]
    for line in lines:
        if line.strip() == '' or len(line)<1:
            continue
        temp={}
        DevData=extract_device_from_macdiscovery(line)
        try:
            temp['ip']=DevData[0]
            temp['mac']=DevData[1]
            temp['name']=DevData[2]
            temp['details']=DevData[3]
            temp['uptime']=DevData[4]
            temp['license']=DevData[5]
            temp['interface']=DevData[6]
            data.append(temp)
        except:
            #print("folowwing line is not valid")
            #print(line)
            pass
    if len(data):
        log.info("Found {} devices ".format(len(data)))
        #ugly hack to reset sequnce number if device id
        database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
        # update device list
        Devices.insert_many(data).on_conflict(conflict_target=Devices.mac,update={Devices.ip:EXCLUDED.ip,Devices.uptime:EXCLUDED.uptime,Devices.name:EXCLUDED.name,Devices.interface:EXCLUDED.interface,Devices.details:EXCLUDED.details}).execute()
    return True



@spool(pass_arguments=True)
def scan_with_ip(*args, **kwargs):
    try:
        task=db_tasks.scanner_job_status()
        task.status=1
        task.save()
        start_ip=kwargs.get('start',False)
        end_ip=kwargs.get('end',False)
        username=kwargs.get('username',False)
        password=kwargs.get('password',False)
        if not start_ip or not end_ip:
            task.status=0
            task.save()
            return True
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        scan_port=kwargs.get('port',False)
        default_user,default_pass=util.get_default_user_pass()
        log.error("stating scan ")
        mikrotiks=[]
        scan_results=[]
        dev_number=0
        info={
            'user':kwargs.get('user','Unknown'),
            'start_ip':start_ip,
            'end_ip':end_ip
        }
        for ip_int in range(int(start_ip), int(end_ip)):
            ip=str(ipaddress.IPv4Address(ip_int))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            result = sock.connect_ex((ip,int(scan_port)))
            if result == 0:
                scan_results.append({})
                scan_results[dev_number]['ip']=ip
                dev={
                'ip':ip
                }
                options={
                    'host':ip,
                    'username':username if username else default_user,
                    'password':password if password else default_pass,
                    'routeros_version':'auto',
                    'port':scan_port,
                    'ssl':False
                }
                router=RouterOSCheckResource(options)
                try:
                    call = router.api.path(
                    "/system/resource"
                    )
                    results = tuple(call)
                    result: Dict[str, str] = results[0]
                    try:
                        call = router.api.path(
                            "/system/routerboard"
                        )
                        routerboard = tuple(call)
                        routerboard: Dict[str, str] = routerboard[0]
                        result.update(routerboard)
                    except Exception as e:
                        if 'no such command' not in str(e):
                            log.error(e)
                        pass
                    try:
                        call = router.api.path(
                            "/system/license"
                        )
                        license = tuple(call)
                        license: Dict[str, str] = license[0]
                        result.update(license)
                    except Exception as e:
                        if 'no such command' not in str(e):
                            log.error(e)
                        pass
                    call = router.api.path(
                        "/system/identity"
                    )
                    name = tuple(call)
                    name: Dict[str, str] = name[0]
                    result.update(name)

                    call = router.api.path(
                        "/interface"
                    )
                    interfaces = list(tuple(call))
                    # interfaces: Dict[str, str] = interfaces[0]
                    result['interfaces']=interfaces

                    call = router.api.path(
                        "/ip/address"
                    )
                    ips = list(tuple(call))
                    result['ips']=ips

                    is_availbe , current , arch , upgrade_availble =util.check_update(options,router) 
                    for p in ips:
                        if ip+"/" in p['address']:
                            current_interface=p['interface']
                            break
                    for inter in interfaces:
                        if inter['name']==current_interface:
                            result['interface']=inter
                            break
                    src_ip=sock.getsockname()[0]
                    device={}
                    device['ip']=ip
                    device['update_availble']=is_availbe
                    device['upgrade_availble']=upgrade_availble
                    device['current_firmware']=current
                    if 'software-id' in result:
                        unique_identifire=result['software-id']
                    elif 'system-id' in result:
                        unique_identifire=result['system-id']
                    else:
                        unique_identifire=ip
                    device['mac']=result['interface']['mac-address'] if "mac-address" in result['interface'] else 'tunnel-'+unique_identifire
                    device['name']=result['name']
                    if 'board-name' in result and 'mdoel' in result:
                        device['details']=result['board-name'] + " " +  result['model'] if result['model']!=result['board-name'] else result['model']
                    elif 'board-name' in result:
                        device['details']=result['board-name']
                    else:
                        device['details']='x86/64'
                    device['uptime']=result['uptime']
                    device['license']=""
                    device['interface']=result['interface']['name']
                    device['user_name']=util.crypt_data(options['username'])
                    device['password']=util.crypt_data(options['password'])
                    device['port']=options['port']
                    device['arch']=result['architecture-name']
                    device['peer_ip']=src_ip
                    mikrotiks.append(device)
                    scan_results[dev_number]['added']=True
                    dev_number+=1
                except Exception as e:
                    scan_results[dev_number]['added']=False
                    scan_results[dev_number]['faileres']=str(e)
                    dev_number+=1
                    log.error(e)
                    continue
            sock.close()
        try:
            db_tasks.add_task_result('ip-scan', json.dumps(scan_results),json.dumps(info))
        except:
            pass
        #ugly hack to reset sequnce number if device id
        database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
        try:
            Devices.insert_many(mikrotiks).on_conflict(conflict_target=Devices.mac,
                                                    update={Devices.ip:EXCLUDED.ip,
                                                            Devices.uptime:EXCLUDED.uptime,
                                                            Devices.name:EXCLUDED.name,
                                                            Devices.interface:EXCLUDED.interface,
                                                            Devices.details:EXCLUDED.details}).execute()
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
        task.status=0
        task.save()
        return True
    except Exception as e:
        log.error(e)
        task.status=0
        task.save()
        return True
    
    
    
    
    
@spool(pass_arguments=True)
def exec_snipet(*args, **kwargs):
    task=db_tasks.exec_snipet_status()
    if not task.status:
        task.status=1
        task.save()
        default_ip=kwargs.get('default_ip',False)
        try:
            if kwargs.get('devices',False) and kwargs.get('task',False):
                devids=kwargs.get('devices',False)
                devs=False
                uid=kwargs.get('uid',False)
                utask=kwargs.get('task',False)
                taskdata=json.loads(utask.data)
                if "0" == devids:
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
                else:
                    devids=devids
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid,devids))
                num_threads = len(devs)
                q = queue.Queue()
                threads = []
                log.error(devs)
                for dev in devs:
                    peer_ip=dev.peer_ip if dev.peer_ip else default_ip
                    if not peer_ip and '[mikrowizard]' in taskdata['snippet']['code']:
                        log.error("no peer ip")
                        num_threads=num_threads-1
                        continue
                    snipet_code=taskdata['snippet']['code']
                    if '[mikrowizard]' in taskdata['snippet']['code']:
                        snipet_code=snipet_code.replace('[mikrowizard]', peer_ip)
                    t = Thread(target=util.run_snippets, args=(dev, snipet_code, q))
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join()
                res=[]
                for _ in range(num_threads):
                    qres=q.get()
                    res.append(qres)
                try:
                    db_tasks.add_task_result('snipet_exec', json.dumps(res),json.dumps(model_to_dict(utask),default=serialize_datetime),utask.id)
                except Exception as e:
                    log.error(e)
                    pass
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False
