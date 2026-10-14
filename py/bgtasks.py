#!/usr/bin/python
# -*- coding: utf-8 -*-

# bgtasks.py: background tasks, which are run in separate worker processes
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi

from uwsgidecorators import spool
from playhouse.shortcuts import model_to_dict
from libs import util,firm_lib
from libs import compat_runner
from libs import task_tracker
from libs import job_control
from libs import config_runner as cfg_runner
import config
import time
import os
import sys
from libs.db import db_tasks,db_device,db_events,db_user_group_perm,db_user_tasks
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import pexpect
import re
from libs.db.db_device import Devices,EXCLUDED,database
from libs.db.db import reset_db
import ipaddress
import socket
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from typing import Dict 
import json
import datetime
import uuid
try:
    from libs import utilpro
    import task_run_pro
    ISPRO=True
except ImportError:
    task_run_pro = None
    ISPRO=False
    pass

try:
    from libs.db.db_pam import DeviceConnections, get_template_for_brand
except ImportError:
    pass

sensor_pile = queue.LifoQueue()
other_sensor_pile = queue.LifoQueue()

# Constants
MAX_CONCURRENT_THREADS = getattr(config, "MAX_CONCURRENT_THREADS", 10)
CANCEL_CHECK_INTERVAL = 10
SOCKET_TIMEOUT = getattr(config, "SOCKET_SCAN_TIMEOUT", 0.2)

# devices.mac is backed by a partial unique index (migration 054) that is unique
# only where mac is non-empty.  ON CONFLICT must repeat that predicate to target
# the partial index instead of a full column constraint.
MAC_CONFLICT_WHERE = (Devices.mac.is_null(False) & (Devices.mac != ''))

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
@task_tracker.track_task(100)
def check_devices_for_update(*args, **kwargs):
    reset_db()
    task=db_tasks.update_check_status()
    if task.action=='cancel':
        cancel_task('Firmware Check',task)
        return False
    if task.status:
        return False
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
                def _check_worker(dev, q):
                    try:
                        if task_tracker.cancel_requested(100):
                            return  # stopped by user: skip devices not started yet
                        util.check_device_firmware_update(dev, q)
                    finally:
                        database.close()

                with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_THREADS, len(devs))) as executor:
                    futures = {executor.submit(_check_worker, dev, q): dev for dev in devs}
                    for future in as_completed(futures):
                        dev = futures[future]
                        try:
                            future.result(timeout=600)
                        except Exception as e:
                            log.error(f"Firmware check worker failure for dev {getattr(dev, 'id', '?')}: {e}")
                            q.put({"id": getattr(dev, "id", None), "update_availble": False, "reason": f"Worker failure: {e}"})
            res = []
            with database.connection_context():
                while not q.empty():
                    try:
                        qres = q.get_nowait()
                        if not qres.get("reason", False):
                            res.append(qres)
                        else:
                            dev_id = qres.get('id', qres.get('devid'))
                            if dev_id:
                                db_events.connection_event(dev_id, 'Firmware updater', qres.get("detail", "connection"), "Critical", 0, qres.get("reason", "problem in Firmware updater"))
                    except queue.Empty:
                        break
                db_device.update_devices_firmware_status(res)
    except Exception as e:
        log.error(e)
        return False
    finally:
        task.status=0
        task.save()
        database.close()
    return False


@spool(pass_arguments=True)
@task_tracker.track_task(110)
def update_device(*args, **kwargs):
    """Queue a firmware update / RouterBOOT upgrade request for the selected devices.

    The firmware mule runs the queued requests (mules/firmware.py): no spooler time limit,
    one worker per router (lease), restart-safe. This spool job only selects the devices
    and queues them, so it finishes in seconds whatever the fleet size."""
    reset_db()
    task = db_tasks.update_job_status()
    task.status = 1
    task.save()
    try:
        devids = kwargs.get('devices', False)
        if not devids:
            return False
        uid = kwargs.get('uid', False)
        current_task = kwargs.get('task', "update")
        if "0" == devids:
            devs = list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
        else:
            devs = list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid, devids.split(",")))
        eligible_devs = []
        for dev in devs:
            # RouterOS firmware operations are MikroTik only
            if dev.device_type and dev.device_type != 'mikrotik':
                continue
            if not dev.update_availble and current_task != "upgrade" and devids == "0":
                continue
            eligible_devs.append(dev)

        if ISPRO and kwargs.get('ptp_safe_ordering', True) and hasattr(utilpro, "order_devices_for_upgrade"):
            try:
                if utilpro.check_license_dev_limit_exp():
                    eligible_devs = utilpro.order_devices_for_upgrade(eligible_devs)
            except Exception as e:
                log.warning(f"Device update ordering skipped: {e}")

        version = kwargs.get('version')
        if current_task != 'upgrade' and version == 'latest_cloud':
            # Pro 'Latest Cloud': newest release of the chosen mikrotik.com channel
            version = None
            if ISPRO and hasattr(utilpro, "latest_cloud_version") and utilpro.check_license_dev_limit_exp():
                version = utilpro.latest_cloud_version(kwargs.get('channel'))
            if not version:
                log.warning("Firmware update: Latest Cloud version not available (Pro license or mikrotik.com) - nothing queued")
                return [{"id": d.id, "status": False, "reason": "Latest Cloud version not available"} for d in eligible_devs]

        if current_task == 'upgrade':
            request = {"kind": "routerboot"}
        else:
            request = {
                "kind": "update",
                "version": version,
                "mode": kwargs.get('mode', 'full'),
                "packages": kwargs.get('packages'),
                "auto_upgrade_rb": kwargs.get('auto_upgrade_rb', True),
                "delivery_method": kwargs.get('delivery_method', 'local_repo'),
                "channel": kwargs.get('channel') if kwargs.get('delivery_method') == 'native' else None,
            }
        res = firm_lib.enqueue_device_updates(eligible_devs, request, origin="user:{}".format(uid))
        queued = sum(1 for r in res if r.get("status"))
        log.info(f"Firmware {current_task}: {queued} device(s) queued, {len(res) - queued} skipped")
        for r in res:
            if not r.get("status"):
                log.info(f"Firmware {current_task} not queued for device {r.get('id')}: {r.get('reason')}")
        return res
    except Exception as e:
        log.error(e)
        return False
    finally:
        task.status = 0
        task.save()
        database.close()


@spool(pass_arguments=True)
def reboot_devices(*args, **kwargs):
    """Reboot the selected MikroTik devices (devices list batch action). Only devices of the
    user; routers in a firmware update or a backup / snippet job are skipped (firm_lib.reboot_device)."""
    reset_db()
    try:
        devids = [x for x in str(kwargs.get('devices') or "").split(",") if x.strip().isdigit()]
        if not devids:
            return False
        uid = kwargs.get('uid', False)
        by = kwargs.get('by', "")
        devs = [d for d in db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid, devids)
                if not d.device_type or d.device_type == 'mikrotik']
        if not devs:
            log.info("Reboot: no MikroTik device of the user among the selected ones")
            return False

        def _reboot(dev):
            try:
                return dev, firm_lib.reboot_device(dev, by=by)
            finally:
                database.close()
        workers = max(1, min(MAX_CONCURRENT_THREADS, len(devs)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(_reboot, devs))
        done = sum(1 for _, (ok, _r) in results if ok)
        log.info(f"Reboot: {done} of {len(results)} device(s) rebooted")
        for dev, (ok, reason) in results:
            if not ok:
                log.warning(f"Reboot of {dev.name} ({dev.ip}) not done: {reason}")
        return True
    except Exception as e:
        log.error(f"Reboot job failed: {e}")
        return False


@spool(pass_arguments=True)
@task_tracker.track_task(140)
def download_firmware(*args, **kwargs):
    reset_db()
    task=db_tasks.downloader_job_status()
    if task.action=='cancel':
        cancel_task('Firmware Download',task)
        return False
    if task.status:
        return False
    task.status=1
    task.save()
    # time.sleep(5)
    try:
        if kwargs.get('version',False):
            ver=kwargs.get('version',False)
            arch=kwargs.get('arch', 'all')
            num_threads = 1
            q = queue.Queue()
            threads = []
            t = Thread(target=firm_lib.download_firmware_to_repository, args=(ver, q, arch))
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
        return False
    finally:
        task.status=0
        task.action='None'
        task.save()
    return False

@spool(pass_arguments=True)
@task_tracker.track_task(120)
def backup_devices(*args, **kwargs):
    """Backup of devices. kwargs: device_ids (list of ids). Older spool files carry
    'devices' (Devices rows) - still accepted. A request that arrives while a backup runs
    is queued (re-spooled), never dropped."""
    reset_db()
    claim = job_control.claim_job(120)
    if claim is None:
        job_control.requeue(backup_devices, kwargs, what="backup")
        return False
    job_control.dequeued("backup_devices", kwargs)
    try:
        device_ids = _ids_from_kwargs(kwargs)
        if not device_ids:
            return False
        results = job_control.run_devices(
            device_ids, _backup_one, deadline=job_control.job_deadline(),
            should_cancel=lambda: task_tracker.cancel_requested(120), skipped=_backup_skipped)
        failed = [r for r in results if r and not r.get("status") and not r.get("skipped")]
        if failed:
            with database.connection_context():
                for r in failed:
                    db_events.connection_event(r["id"], 'Backup', r.get("detail", "connection"), "Critical", 0,
                                               r.get("reason") or "problem in getting backup for device")
        log.info("Backup job: %d devices, %d ok, %d failed, %d not run", len(results),
                 sum(1 for r in results if r and r.get("status") and not r.get("skipped")), len(failed),
                 sum(1 for r in results if r and r.get("skipped")))
    except Exception as e:
        log.exception("backup_devices failed: %s", e)
        return False
    finally:
        job_control.release_job(claim)
    return False


def _ids_from_kwargs(kwargs):
    ids = kwargs.get('device_ids')
    if ids is None:
        ids = [getattr(d, 'id', d) for d in (kwargs.get('devices') or [])]
    out = []
    for i in ids or []:
        try:
            out.append(int(i))
        except (TypeError, ValueError):
            continue
    return list(dict.fromkeys(out))


def _backup_one(dev_id):
    res = cfg_runner.run_device_job({"device_id": dev_id, "command_key": "show_config"})
    ok = res.get("status") == "ok"
    out = {"id": dev_id, "devid": dev_id, "devip": res.get("device_ip", ""), "devname": res.get("device_name", ""),
           "status": ok, "state": ok}
    if not ok:
        out["reason"] = (res.get("error") or "problem in getting backup for device")[:500]
        out["detail"] = {"auth_error": "auth", "timeout": "timeout"}.get(res.get("status"), "connection")
    return out


def _backup_skipped(dev_id, reason, message):
    if reason not in (job_control.SKIP_BUSY, job_control.SKIP_CANCELLED, job_control.SKIP_DEADLINE):
        return {"id": dev_id, "devid": dev_id, "devip": "", "status": False, "state": False,
                "reason": message, "detail": "Worker error"}
    # not run (stop, time limit, router busy with another job): no failure event
    return {"id": dev_id, "devid": dev_id, "devip": "", "status": False, "state": False, "skipped": reason,
            "cancelled": reason == job_control.SKIP_CANCELLED, "reason": message}

def _create_default_connections(mikrotiks):
    try:
        macs = [d['mac'] for d in mikrotiks]
        inserted_devices = list(Devices.select().where(Devices.mac.in_(macs)))
        now = datetime.datetime.now(datetime.timezone.utc)
        by_mac = {m['mac']: m for m in mikrotiks}
        for dev in inserted_devices:
            m_data = by_mac.get(dev.mac)
            if not m_data:
                continue
            api_port = m_data.get('port') or 8728
            # API connection (MikroTik default)
            if not DeviceConnections.select().where(DeviceConnections.device_id == dev.id, DeviceConnections.protocol == 'api').exists():
                DeviceConnections.create(device_id=dev.id, protocol='api', port=api_port, auth_mode='credential', is_default=True, created=now, modified=now)
            # Default SSH
            if not DeviceConnections.select().where(DeviceConnections.device_id == dev.id, DeviceConnections.protocol == 'ssh').exists():
                DeviceConnections.create(device_id=dev.id, protocol='ssh', port=22, auth_mode='credential', is_default=False, created=now, modified=now)
            # Default WebFig
            if not DeviceConnections.select().where(DeviceConnections.device_id == dev.id, DeviceConnections.protocol == 'webfig').exists():
                DeviceConnections.create(device_id=dev.id, protocol='webfig', port=80, auth_mode='credential', is_default=False, created=now, modified=now)
    except Exception as e:
        log.error(f"Error creating DeviceConnections for bulk added devices: {e}")


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
@task_tracker.track_task(130)
def scan_with_mac(timer=2):
    reset_db()
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
            temp['device_type']='mikrotik'
            data.append(temp)
        except:
            #print("folowwing line is not valid")
            #print(line)
            pass
    if len(data):
        log.info("Found {} devices ".format(len(data)))
        
        # Deduplicate data by mac
        unique_data = {}
        for item in data:
            if item['mac'] in unique_data:
                log.debug(f"Scan MAC duplicate found: {item['mac']}, keeping latest (IP: {item['ip']})")
            unique_data[item['mac']] = item
        data = list(unique_data.values())

        #ugly hack to reset sequnce number if device id
        database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
        # update device list
        Devices.insert_many(data).on_conflict(conflict_target=Devices.mac,conflict_where=MAC_CONFLICT_WHERE,update={Devices.ip:EXCLUDED.ip,Devices.uptime:EXCLUDED.uptime,Devices.name:EXCLUDED.name,Devices.interface:EXCLUDED.interface,Devices.details:EXCLUDED.details,Devices.device_type:EXCLUDED.device_type}).execute()
    return True



@spool(pass_arguments=True)
@task_tracker.track_task(130)
def scan_with_ip(*args, **kwargs):
    reset_db()
    task=None
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
        ssl=kwargs.get('ssl',False)
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
                        'ssl':bool(ssl),
                        'hostname':None,
                        'ssl_cafile':None,
                        'ssl_capath':None,
                        'ssl_force_no_certificate':False,
                        'ssl_verify':False,
                        'ssl_verify_hostname':False
                    }
                    router = None
                    try:
                        router=RouterOSCheckResource(options)
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
                        device['peer_ip']=src_ip
                        
                        # Identify device: Try current interface MAC first, then search all interfaces
                        mac = result['interface'].get('mac-address')
                        if not mac or mac == '00:00:00:00:00:00':
                            # Prioritize physical interfaces (ether, wlan) for a more stable identity
                            physical_interfaces = [i for i in interfaces if i.get('type') in ['ether', 'wlan']]
                            # Search prioritized physical interfaces first
                            for inter in physical_interfaces:
                                m = inter.get('mac-address')
                                if m and m != '00:00:00:00:00:00':
                                    mac = m
                                    break
                            
                            # Fallback to any other interface with a MAC if no physical ones found
                            if not mac or mac == '00:00:00:00:00:00':
                                for inter in interfaces:
                                    m = inter.get('mac-address')
                                    if m and m != '00:00:00:00:00:00':
                                        mac = m
                                        break
                        
                        if mac and mac != '00:00:00:00:00:00':
                            device['mac'] = mac
                            log.debug(f"Device {ip} identified with MAC: {device['mac']}")
                        else:
                            # Fallback to T- prefix and unique_identifire (Software-ID/System-ID)
                            device['mac'] = f"T-{unique_identifire}"
                            log.debug(f"Device {ip} has no physical MAC, using tunnel ID: {device['mac']}")

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
                        device['ssl']=options['ssl']
                        device['arch']=result['architecture-name']
                        device['device_type']='mikrotik'
                        mikrotiks.append(device)
                        scan_results[dev_number]['added']=True
                        dev_number+=1
                    except Exception as e:
                        scan_results[dev_number]['added']=False
                        scan_results[dev_number]['faileres']="Connection or authentication failed"
                        dev_number+=1
                        log.error(f"Error scanning {ip}: {e}")
                        continue
                    finally:
                        if router:
                            router.close()
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
        
        if mikrotiks:
            try:
                log.info(f"Inserting/Updating {len(mikrotiks)} devices in database")
                # Using on_conflict to update existing devices if they have the same MAC
                Devices.insert_many(mikrotiks).on_conflict(conflict_target=Devices.mac,
                                                        conflict_where=MAC_CONFLICT_WHERE,
                                                        update={Devices.ip:EXCLUDED.ip,
                                                                Devices.uptime:EXCLUDED.uptime,
                                                                Devices.name:EXCLUDED.name,
                                                                Devices.interface:EXCLUDED.interface,
                                                                Devices.details:EXCLUDED.details,
                                                                Devices.ssl:EXCLUDED.ssl,
                                                                Devices.port:EXCLUDED.port,
                                                                Devices.device_type:EXCLUDED.device_type}).execute()
            except Exception as e:
                if "ON CONFLICT DO UPDATE command cannot affect row a second time" in str(e):
                    log.warning("Duplicate MACs found in the same scan batch. This usually means multiple IPs for the same device. Retrying with deduplication...")
                    unique_mikrotiks = {dev['mac']: dev for dev in mikrotiks}
                    Devices.insert_many(list(unique_mikrotiks.values())).on_conflict(conflict_target=Devices.mac,
                                                        conflict_where=MAC_CONFLICT_WHERE,
                                                        update={Devices.ip:EXCLUDED.ip,
                                                                Devices.uptime:EXCLUDED.uptime,
                                                                Devices.name:EXCLUDED.name,
                                                                Devices.interface:EXCLUDED.interface,
                                                                Devices.details:EXCLUDED.details,
                                                                Devices.ssl:EXCLUDED.ssl,
                                                                Devices.port:EXCLUDED.port,
                                                                Devices.device_type:EXCLUDED.device_type}).execute()
                else:
                    log.error(f"Database insertion failed: {e}")
                    task.status=0
                    task.save()
        task.status=0
        task.save()
        return True
    except Exception as e:
        log.error(e)
        return True
    finally:
        if task:
            task.status=0
            task.save()

@spool(pass_arguments=True)
@task_tracker.track_task(160)
def exec_snipet(*args, **kwargs):
    """Run a snippet task on devices. kwargs: utask_id (user task id) or task (row, older
    spool files), devices ("0" = all devices of the user, or list of ids), uid. A request
    that arrives while another snippet job runs is queued, never dropped."""
    reset_db()
    claim = job_control.claim_job(160)
    if claim is None:
        job_control.requeue(exec_snipet, kwargs, what="snippet")
        return False
    job_control.dequeued("exec_snipet", kwargs)
    try:
        devids = kwargs.get('devices', False)
        uid = kwargs.get('uid', False)
        with database.connection_context():
            utask = kwargs.get('task', False)
            if kwargs.get('utask_id'):
                utask = db_user_tasks.UserTasks.get_or_none(db_user_tasks.UserTasks.id == int(kwargs['utask_id']))
            if not devids or not utask:
                return False
            taskdata = json.loads(utask.data)
            if "0" == devids:
                devs = list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
            else:
                devs = list(db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid, devids))
            device_ids = list(dict.fromkeys(d.id for d in devs))
        code = taskdata['snippet']['code']
        store_in_backup = bool(taskdata.get('store_in_backup', False))
        snippet_id = taskdata.get('snippet', {}).get('id')
        utask_id = utask.id

        def _one(dev_id):
            return _snippet_one(dev_id, code, utask_id, snippet_id, store_in_backup)

        res = job_control.run_devices(
            device_ids, _one, deadline=job_control.job_deadline(),
            should_cancel=lambda: task_tracker.cancel_requested(160), skipped=_snippet_skipped)
        log.info("Snippet task %s: %d devices, %d ok", utask_id, len(res),
                 sum(1 for r in res if r and r.get("status")))
        try:
            with database.connection_context():
                db_tasks.add_task_result('snipet_exec', json.dumps(res), json.dumps(model_to_dict(utask), default=serialize_datetime), utask_id)
        except Exception as e:
            log.error("snippet results of task %s not saved: %s", utask_id, e)
    except Exception as e:
        log.exception("exec_snipet failed: %s", e)
        return False
    finally:
        job_control.release_job(claim)
    return False


def _snippet_one(dev_id, code, utask_id, snippet_id, store_in_backup):
    """One device of a snippet job; result in the format the UI shows."""
    with database.connection_context():
        dev = Devices.get_by_id(dev_id)
        devip, devname = dev.ip, getattr(dev, "name", "")
        if '[mikrowizard]' in code:
            peer_ip = util.resolve_peer_ip(dev)
            if not peer_ip:
                return {"id": dev_id, "devid": dev_id, "devip": devip, "devname": devname, "status": False,
                        "state": False, "result": "Exec Failed: MikroWizard server address unknown for this "
                                                  "device ([mikrowizard] needs the peer IP or the default IP)"}
            code = code.replace('[mikrowizard]', peer_ip)
    r = cfg_runner.run_device_job({
        "device_id": dev_id, "snippet_content": code, "snippet_id": snippet_id, "command_key": None,
        "user_task_id": utask_id, "capture_output": True, "store_in_backup": store_in_backup,
        "skip_versioning": not store_in_backup,
    })
    ok = r.get("status") == "ok"
    if ok:
        result = r.get("output_raw") or r.get("output_normalized") or "executed successfully"
    else:
        result = "Exec Failed: {}".format(r.get("error") or "unknown error")
    return {"id": dev_id, "devid": dev_id, "devip": devip, "devname": devname, "status": ok, "state": ok,
            "result": result}


def _snippet_skipped(dev_id, reason, message):
    return {"id": dev_id, "devid": dev_id, "devip": "", "devname": "", "status": False, "state": False,
            "result": message if reason != "error" else "Exec Failed: " + message, "skipped": reason}

@spool(pass_arguments=True)
@task_tracker.track_task(185)
def exec_multi_brand(*args, **kwargs):
    """Multi-brand execution of one run (kwargs run_id = execution_run_id returned by the API).
    Each run has its own tasks row (task_id = run id): status, stop and logs all use it."""
    reset_db()
    run_id = kwargs.get("run_id") or kwargs.get("task_id")
    if not run_id:
        run_id = str(uuid.uuid4())       # spool file of an older version
        kwargs["run_id"] = run_id
    job_control.ensure_task_row(185, "Multi-Brand Exec", run_id)
    claim = job_control.claim_job(185, task_id=run_id)
    if claim is None:
        job_control.requeue(exec_multi_brand, kwargs, what="execution")
        return False
    job_control.dequeued("exec_multi_brand", kwargs)
    try:
        devices = kwargs.get("devices", [])
        device_ids = kwargs.get("device_ids", [])
        if not device_ids and devices:
            device_ids = [d.id for d in devices]
        if not device_ids:
            return False
        user_task_id = kwargs.get("user_task_id")
        job_config = {
            "device_ids": device_ids,
            "execution_run_id": run_id,
            "command_key": kwargs.get("command_key"),
            "custom_command": kwargs.get("custom_command"),
            "snippet_id": kwargs.get("snippet_id"),
            "snippet_content": kwargs.get("snippet_content"),
            "is_config_mode": kwargs.get("is_config_mode", False),
            "user_task_id": user_task_id,
            "deadline": job_control.job_deadline(),
            "should_cancel": lambda: task_tracker.cancel_requested(185, run_id),
        }
        results = cfg_runner.run_bulk_job(job_config)
        try:
            with database.connection_context():
                db_tasks.add_task_result(
                    "multi_brand_exec",
                    json.dumps(results),
                    json.dumps({"device_ids": device_ids, "user_task_id": user_task_id, "execution_run_id": run_id},
                               default=serialize_datetime),
                    user_task_id,
                )
        except Exception as e:
            log.error("exec_multi_brand add_task_result failed: %s", e)
    except Exception as e:
        log.exception("exec_multi_brand: %s", e)
        return False
    finally:
        job_control.release_job(claim)
        job_control.prune_run_rows(185)
    return False

@spool(pass_arguments=True)
@task_tracker.track_task(175)
def exec_sequence(*args, **kwargs):
    """Run a sequence task. kwargs: utask_id (or utask row, older spool files). A request that
    arrives while another sequence runs is queued, never dropped."""
    reset_db()
    if not ISPRO:
        return False
    claim = job_control.claim_job(175)
    if claim is None:
        job_control.requeue(exec_sequence, kwargs, what="sequence")
        return False
    job_control.dequeued("exec_sequence", kwargs)
    try:
        utask = kwargs.get('utask', False)
        if kwargs.get('utask_id'):
            with database.connection_context():
                utask = db_user_tasks.UserTasks.get_or_none(db_user_tasks.UserTasks.id == int(kwargs['utask_id']))
        if utask and task_run_pro:
            res = task_run_pro.run_sequence_task(utask, deadline=job_control.job_deadline())
            log.info("Sequence task %s executed on %d devices", utask.id, len(res or []))
            try:
                with database.connection_context():
                    db_tasks.add_task_result('sequence_exec', json.dumps(res), json.dumps(model_to_dict(utask), default=serialize_datetime), utask.id)
            except Exception as e:
                log.error("sequence results of task %s not saved: %s", utask.id, e)
    except Exception as e:
        log.exception("exec_sequence failed: %s", e)
        return False
    finally:
        job_control.release_job(claim)
    return False

@spool(pass_arguments=True)
@task_tracker.track_task(170)
def exec_vault(*args, **kwargs):
    reset_db()
    Tasks=db_tasks.Tasks
    try:
        task=Tasks.select().where(Tasks.signal == 170).get()
    except Tasks.DoesNotExist:
        return False
    if(task.action=='cancel'):
        cancel_task('Vault Exec',task)
        return False
    if not ISPRO:
        return False
    if task.status:
        return False
    task.status=1
    task.save()
    try:
        utask=kwargs.get('utask',False)
        res=utilpro.run_vault_task(utask)
    except Exception as e:
        log.error(e)
        return False
    finally:
        task.status=0
        task.save()
    return False

@spool(pass_arguments=True)
@task_tracker.track_task(180)
def bulk_add_devices(*args, **kwargs):
    reset_db()
    task=None
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
        if kwargs.get('payload_id'):
            devices=job_control.load_payload(kwargs['payload_id']) or []
        task_id=kwargs.get('task_id','')
        
        if not devices:
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
        default_template_id = None
        try:
            mikrotik_template = get_template_for_brand("mikrotik")
            if mikrotik_template:
                default_template_id = mikrotik_template.id
        except Exception:
            pass
        
        for idx, device_info in enumerate(devices):
            task=db_tasks.get_bulk_add_task(task_id)
            if task and task.action=='cancel':
                cancel_task('Bulk Add',task)
                return False
                
            ip = device_info['ip']
            log.info(f"Adding device {ip}")
            username = device_info['username']
            password = device_info['password']
            ssl = device_info.get('ssl', False)
            port = device_info.get('port') or (8729 if ssl else 8728)
            if int(port) == 8729 and 'ssl' not in device_info:
                ssl = True
            
            scan_results.append({'ip': ip})
            ip = str(ipaddress.IPv4Address(ip))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            src_ip = None
            try:
                sock.settimeout(SOCKET_TIMEOUT)
                result = sock.connect_ex((ip, int(port)))
                if result != 0:
                    # Auto-probe 8729 (SSL) if default 8728 was unreachable
                    if int(port) == 8728 and 'port' not in device_info:
                        try:
                            sock.close()
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(SOCKET_TIMEOUT)
                            if sock.connect_ex((ip, 8729)) == 0:
                                port = 8729
                                ssl = True
                                result = 0
                                src_ip = sock.getsockname()[0]
                        except Exception:
                            pass
                    if result != 0:
                        scan_results[idx]['added'] = False
                        scan_results[idx]['failures'] = "Connection or authentication failed"
                        log.error(f"Error adding device {ip}: port {port} unreachable")
                        continue
                if not src_ip:
                    src_ip = sock.getsockname()[0]
            except Exception as e:
                scan_results[idx]['added'] = False
                scan_results[idx]['failures'] = "Connection or authentication failed"
                log.error(f"Error adding device {ip}: {e}")
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            options={
                'host':ip,
                'username':username,
                'password':password,
                'routeros_version':'auto',
                'port':port,
                'ssl':bool(ssl),
                'hostname':None,
                'ssl_cafile':None,
                'ssl_capath':None,
                'ssl_force_no_certificate':False,
                'ssl_verify':False,
                'ssl_verify_hostname':False
            }
            
            router = None
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
                
                # Identify device: Try current interface MAC first, then search all interfaces
                mac = result['interface'].get('mac-address')
                if not mac or mac == '00:00:00:00:00:00':
                    # Prioritize physical interfaces (ether, wlan) for a more stable identity
                    physical_interfaces = [i for i in interfaces if i.get('type') in ['ether', 'wlan']]
                    # Search prioritized physical interfaces first
                    for inter in physical_interfaces:
                        m = inter.get('mac-address')
                        if m and m != '00:00:00:00:00:00':
                            mac = m
                            break
                    
                    # Fallback to any other interface with a MAC if no physical ones found
                    if not mac or mac == '00:00:00:00:00:00':
                        for inter in interfaces:
                            m = inter.get('mac-address')
                            if m and m != '00:00:00:00:00:00':
                                mac = m
                                break
                
                if mac and mac != '00:00:00:00:00:00':
                    device['mac'] = mac
                    log.debug(f"Bulk Add: Device {ip} identified with MAC: {device['mac']}")
                else:
                    # Fallback to T- prefix and unique_identifire (Software-ID/System-ID)
                    device['mac'] = f"T-{unique_identifire}"
                    log.debug(f"Bulk Add: Device {ip} has no physical MAC, using tunnel ID: {device['mac']}")

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
                device['port']=options['port']
                device['ssl']=options['ssl']
                device['arch']=result['architecture-name']
                device['device_type']='mikrotik'
                if default_template_id:
                    device['template_id'] = default_template_id
                device['peer_ip']=src_ip 
                mikrotiks.append(device)

                scan_results[idx]['added']=True
                
            except Exception as e:
                scan_results[idx]['added']=False
                scan_results[idx]['failures']="Connection or authentication failed"
                log.error(f"Error adding device {ip}: {e}")
            finally:
                if router:
                    router.close()
                
        try:
            db_tasks.add_task_result('bulk-add', json.dumps(scan_results), json.dumps(info,default=serialize_datetime))
        except Exception as e:
            log.error(e)
            
        database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
        
        try:
            if mikrotiks:
                log.info(f"Bulk Add: Inserting/Updating {len(mikrotiks)} devices in database")
                update_fields = {Devices.ip:EXCLUDED.ip,
                                 Devices.uptime:EXCLUDED.uptime,
                                 Devices.name:EXCLUDED.name,
                                 Devices.interface:EXCLUDED.interface,
                                 Devices.details:EXCLUDED.details,
                                 Devices.ssl:EXCLUDED.ssl,
                                 Devices.port:EXCLUDED.port,
                                 Devices.device_type:EXCLUDED.device_type,
                                 Devices.template_id:EXCLUDED.template_id}
                try:
                    Devices.insert_many(mikrotiks).on_conflict(conflict_target=Devices.mac,
                                                               conflict_where=MAC_CONFLICT_WHERE,
                                                               update=update_fields).execute()
                except Exception as e:
                    if "ON CONFLICT DO UPDATE command cannot affect row a second time" not in str(e):
                        raise
                    log.warning("Bulk Add: Duplicate MACs in same batch. Retrying with deduplication...")
                    unique_mikrotiks = {dev['mac']: dev for dev in mikrotiks}
                    Devices.insert_many(list(unique_mikrotiks.values())).on_conflict(conflict_target=Devices.mac,
                                                                                     conflict_where=MAC_CONFLICT_WHERE,
                                                                                     update=update_fields).execute()
                # Task 18.3 & 18.1: default DeviceConnections (api / ssh / webfig) of the added devices
                _create_default_connections(mikrotiks)
        except Exception as e:
            log.error(e)
            
        return True
        
    except Exception as e:
        log.error(e)
        return True
    finally:
        if kwargs.get('payload_id'):
            job_control.drop_payload(kwargs['payload_id'])
        if task:
            task.status=0
            task.save()


# Spool functions of other modules: the spooler imports only this module (spooler-import),
# so they must be registered from here to be runnable by the spooler.
import bgtasks_non_mikrotik  # noqa: E402,F401
