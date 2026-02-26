#!/usr/bin/python
# -*- coding: utf-8 -*-

# bgtasks.py: background tasks, which are run in separate worker processes
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi

from uwsgidecorators import spool
from playhouse.shortcuts import model_to_dict
from libs import util,firm_lib
import time
from libs.db import db_tasks,db_device,db_events,db_user_group_perm
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
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
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

sensor_pile = queue.LifoQueue()
other_sensor_pile = queue.LifoQueue()

# Constants
MAX_CONCURRENT_THREADS = 10
CANCEL_CHECK_INTERVAL = 10
SOCKET_TIMEOUT = 0.2

import logging
log = logging.getLogger("bgtasks")

def serialize_datetime(obj): 
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 

def cancel_task(task_name='',task=0):
    log.info(f"Canceling task {task_name}")
    task.action='None'
    task.status=0
    task.save()
    return True

@spool(pass_arguments=True)
def check_devices_for_update(*args, **kwargs):
    task=db_tasks.update_check_status()
    if task.action=='cancel':
        cancel_task('Firmware Check',task)
        return False
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
                if devs:
                    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_THREADS, len(devs))) as executor:
                        futures = [executor.submit(util.check_device_firmware_update, dev, q) for dev in devs]
                        for future in futures:
                            future.result()
                res=[]
                for _ in range(num_threads):
                    qres=q.get()
                    if not qres.get("reason",False):
                        res.append(qres)
                    else:
                        db_events.connection_event(qres['id'],'Firmware updater',qres.get("detail","connection"),"Critical",0,qres.get("reason","problem in Firmware updater"))
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
    if task.action=='cancel':
        cancel_task('Firmware Update',task)
        return False
    if not task.status:
        task.status=1
        task.save()
        try:
            if kwargs.get('devices',False):
                devids=kwargs.get('devices',False)
                devs=False
                uid=kwargs.get('uid',False)
                current_task=kwargs.get('task',"update")
                if "0" == devids:
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
                else:
                    devids=devids.split(",")
                    devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid,devids))
                num_threads = len(devs)
                q = queue.Queue()
                eligible_devs = []
                for dev in devs:
                    if current_task=='upgrade':
                        if not dev.upgrade_device:
                            dev.upgrade_device = True
                            dev.save()
                    if dev.failed_attempt>0:
                        dev.failed_attempt=0
                        dev.save()
                    if(not dev.update_availble and current_task != "upgrade"):
                        continue
                    eligible_devs.append(dev)
                if eligible_devs:
                    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_THREADS, len(eligible_devs))) as executor:
                        futures = [executor.submit(firm_lib.update_device, dev, q) for dev in eligible_devs]
                        for future in futures:
                            future.result()
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
    if task.action=='cancel':
        cancel_task('Firmware Download',task)
        return False
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
                t = Thread(target=firm_lib.download_firmware_to_repository, args=(ver, q))
                t.start()
                threads.append(t)
                for t in threads:
                    t.join()
                res=[]
                for _ in range(num_threads):
                    action=db_tasks.downloader_job_status().action
                    if action=='cancel':
                        cancel_task('Firmware Download',task)
                        return False
                    qres=q.get()
                # db_device.update_devices_firmware_status(res)
        except Exception as e:
            log.error(e)
            task.status=0
            task.action='None'
            task.save()
            return False
    task.status=0
    task.action='None'
    task.save()
    return False

@spool(pass_arguments=True)
def backup_devices(*args, **kwargs):
    task=db_tasks.backup_job_status()
    if task.action=='cancel':
        cancel_task('Backup',task)
        return False
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
                    if devices:
                        with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_THREADS, len(devices))) as executor:
                            futures = [executor.submit(util.backup_routers, dev, q) for dev in devices]
                            for future in futures:
                                future.result()
                    res=[]
                    for _ in range(num_threads):
                        qres=q.get()
                        if not qres['status']:
                            if 'id' in qres:
                                db_events.connection_event(qres['id'], 'Backup', qres.get("detail", "connection"), "Critical", 0, qres.get("reason", "problem in getting backup for device"))
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
    task=db_tasks.scanner_job_status()
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
        if task.action=='cancel':
            cancel_task('IP Scan',task)
            return False
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
        now=datetime.datetime.now(datetime.timezone.utc)
        #datetime to string fomat %Y-%m-%dT%H:%M:%S
        now=now.strftime("%Y-%m-%dT%H:%M:%S")
        info={
            'username':kwargs.get('username','Unknown'),
            'start_ip':start_ip,
            'end_ip':end_ip,
            'created':now
        }
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        scan_port=kwargs.get('port',False)
        default_user,default_pass=util.get_default_user_pass()
        log.error("starting scan ")
        mikrotiks=[]
        scan_results=[]
        dev_number=0
        cancel_check_counter = 0
        for ip_int in range(int(start_ip), int(end_ip)+1):
            cancel_check_counter += 1
            if cancel_check_counter % CANCEL_CHECK_INTERVAL == 0:
                task=db_tasks.scanner_job_status()
                if task.action=='cancel':
                    cancel_task('IP Scan',task)
                    return False
            ip=str(ipaddress.IPv4Address(ip_int))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(SOCKET_TIMEOUT)
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
                        current_interface = None
                        for p in ips:
                            if ip+"/" in p['address'] and not p.get('invalid', False):
                                current_interface=p['interface']
                                break
                        
                        if current_interface:
                            for inter in interfaces:
                                if inter['name']==current_interface:
                                    result['interface']=inter
                                    break
                        else:
                            # Use first interface as fallback
                            result['interface'] = interfaces[0] if interfaces else {}
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
                        if 'board-name' in result and 'model' in result:
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
                        scan_results[dev_number]['faileres']="Connection or authentication failed"
                        dev_number+=1
                        log.error(f"Error scanning {ip}: {e}")
                        continue
                else:
                    scan_results.append({})
                    scan_results[dev_number]['ip']=ip
                    scan_results[dev_number]['added']=False
                    scan_results[dev_number]['faileres']="Not MikroTik or Device/Api Port not accessible"
                    dev_number+=1
            finally:
                sock.close()
        try:
            db_tasks.add_task_result('ip-scan', json.dumps(scan_results),json.dumps(info,default=serialize_datetime))
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
    if task.action=='cancel':
        cancel_task('Snipet Exec',task)
        return False
    if not task.status:
        task.status=1
        task.save()
        now=datetime.datetime.now()
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
                eligible_devs = []
                for dev in devs:
                    peer_ip=dev.peer_ip if dev.peer_ip else default_ip
                    if not peer_ip and '[mikrowizard]' in taskdata['snippet']['code']:
                        log.error("no peer ip")
                        num_threads=num_threads-1
                        continue
                    snipet_code=taskdata['snippet']['code']
                    if '[mikrowizard]' in taskdata['snippet']['code']:
                        snipet_code=snipet_code.replace('[mikrowizard]', peer_ip)
                    eligible_devs.append((dev, snipet_code))
                
                if eligible_devs:
                    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_THREADS, len(eligible_devs))) as executor:
                        futures = [executor.submit(util.run_snippets, dev, code, q) for dev, code in eligible_devs]
                        for future in futures:
                            future.result()
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

@spool(pass_arguments=True)
def exec_vault(*args, **kwargs):
    Tasks=db_tasks.Tasks
    task=Tasks.select().where(Tasks.signal == 170).get()
    if(task.action=='cancel'):
        cancel_task('Vault Exec',task)
        return False
    if not ISPRO:
        return False
    if not task.status:
        try:
            task.status=1
            task.save()
            utask=kwargs.get('utask',False)
            res=utilpro.run_vault_task(utask)
        except Exception as e:
            log.error(e)
            task.status=0
            task.save()
            return False
    task.status=0
    task.save()
    return False

@spool(pass_arguments=True)
def bulk_add_devices(*args, **kwargs):
    try:
        task_id=kwargs.get('task_id','')
        task=db_tasks.get_bulk_add_task(task_id)
        if not task:
            return False
        if task.action=='cancel':
            cancel_task('Bulk Add',task)
            return False
        task.status=1
        task.save()
        
        devices=kwargs.get('devices',[])
        task_id=kwargs.get('task_id','')
        
        if not devices:
            task.status=0
            task.save()
            return True
            
        now=datetime.datetime.now(datetime.timezone.utc)
        info={
            'task_id':task_id,
            'user':kwargs.get('user','Unknown'),
            'device_count':len(devices),
            'created':now.strftime("%Y-%m-%dT%H:%M:%S")
        }
        
        mikrotiks=[]
        scan_results=[]
        
        for idx, device_info in enumerate(devices):
            task=db_tasks.get_bulk_add_task(task_id)
            if task and task.action=='cancel':
                cancel_task('Bulk Add',task)
                return False
                
            ip = device_info['ip']
            log.info(f"Adding device {ip}")
            username = device_info['username']
            password = device_info['password']
            port = device_info.get('port', 8728)
            
            scan_results.append({'ip': ip})
            ip=str(ipaddress.IPv4Address(ip))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(SOCKET_TIMEOUT)
                result = sock.connect_ex((ip,int(port)))
                if result != 0:
                    scan_results[idx]['added']=False
                    scan_results[idx]['failures']="Connection or authentication failed"
                    log.error(f"Error adding device {ip}")
                else:
                    src_ip=sock.getsockname()[0]
            except Exception as e:
                scan_results[idx]['added']=False
                scan_results[idx]['failures']="Connection or authentication failed"
                log.error(f"Error adding device {ip}: {e}")
                continue
            options={
                'host':ip,
                'username':username,
                'password':password,
                'routeros_version':'auto',
                'port':port,
                'ssl':False
            }
            
            try:
                router=RouterOSCheckResource(options)
                call = router.api.path("/system/resource")
                results = tuple(call)
                result = results[0]
                
                try:
                    call = router.api.path("/system/routerboard")
                    routerboard = tuple(call)
                    result.update(routerboard[0])
                except:
                    pass
                    
                try:
                    call = router.api.path("/system/license")
                    license = tuple(call)
                    result.update(license[0])
                except:
                    pass
                    
                call = router.api.path("/system/identity")
                name = tuple(call)
                result.update(name[0])
                
                call = router.api.path("/interface")
                interfaces = list(tuple(call))
                result['interfaces']=interfaces
                
                call = router.api.path("/ip/address")
                ips = list(tuple(call))
                result['ips']=ips
                is_availbe, current, arch, upgrade_availble = util.check_update(options,router)
                current_interface = None
                for p in ips:
                    if ip+"/" in p['address'] and not p.get('invalid', False):
                        current_interface=p['interface']
                        break
                if current_interface:
                    for inter in interfaces:
                        if inter['name']==current_interface:
                            result['interface']=inter
                            break
                else:
                    result['interface'] = interfaces[0] if interfaces else {}
                    
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
                
                if 'board-name' in result and 'model' in result:
                    device['details']=result['board-name'] + " " + result['model'] if result['model']!=result['board-name'] else result['model']
                elif 'board-name' in result:
                    device['details']=result['board-name']
                else:
                    device['details']='x86/64'
                device['uptime']=result['uptime']
                device['license']=""
                device['interface']=result['interface']['name']
                device['user_name']=util.crypt_data(username)
                device['password']=util.crypt_data(password)
                device['port']=port
                device['arch']=result['architecture-name']
                device['port']=options['port']
                device['arch']=result['architecture-name']
                device['peer_ip']=src_ip 
                mikrotiks.append(device)

                scan_results[idx]['added']=True
                
            except Exception as e:
                scan_results[idx]['added']=False
                scan_results[idx]['failures']="Connection or authentication failed"
                log.error(f"Error adding device {ip}: {e}")
                
        try:
            db_tasks.add_task_result('bulk-add', json.dumps(scan_results), json.dumps(info,default=serialize_datetime))
        except Exception as e:
            log.error(e)
            
        database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
        
        try:
            if mikrotiks:
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
        return True
        
    except Exception as e:
        log.error(e)
        task.status=0
        task.save()
        return True
