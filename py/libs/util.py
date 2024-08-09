#!/usr/bin/python
# -*- coding: utf-8 -*-

# util.py: functions that we need :)
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import pytz
import datetime
import time
import uuid
import socket
import config
from libs.db import db_sysconfig,db_firmware,db_backups,db_events
from cryptography.fernet import Fernet 
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.check_routeros.routeros_check.helper import  RouterOSVersion
from typing import  Dict
import re
import json 
import logging
from libs.red import RedisDB
from libs.ssh_helper import SSH_Helper
import os
from bs4 import BeautifulSoup
import urllib.request
import hashlib
import netifaces
log = logging.getLogger("util")
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
import zipfile
# --------------------------------------------------------------------------
# date related common methods

tz_hki = pytz.timezone("UTC")
tz_utc = pytz.utc

def utc2local(utc_dt, tz=tz_hki):
    """Convert UTC into local time, given tz."""
    if type(tz) is str:
        tz = pytz.timezone(tz)

    if not utc_dt:
        return utc_dt

    d = utc_dt.replace(tzinfo=tz_utc)
    return d.astimezone(tz)

def local2utc(local_dt, tz=tz_hki):
    """Convert local time into UTC."""

    if not local_dt:
        return local_dt

    d = local_dt.replace(tzinfo=tz)
    return d.astimezone(tz_utc)

def utcnow():
    """Return UTC now."""
    return datetime.datetime.utcnow()

def generate_token():
    """Generate a random token
    (an uuid like 8491997531e44d37ac3105b300774e08)"""
    return uuid.uuid4().hex

def check_port(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((ip,int(port)))
    sock.close()
    if result == 0:
        return True
    else:
        return False

def crypt_data(text):
    # Encryption: Encrypting password using Fernet symmetric encryption 
    cipher_suite = Fernet(config.CRYPT_KEY) 
    # Encrypting 
    encrypted_password = cipher_suite.encrypt(text.encode()).decode() 
    return encrypted_password
     

def decrypt_data(text):
    # Encryption: Decrypting password using Fernet symmetric encryption 
    cipher_suite = Fernet(config.CRYPT_KEY) 
    # Decrypting password 
    decrypted_password = cipher_suite.decrypt(text.encode()).decode()
    return decrypted_password

def get_default_user_pass():
    default_user = db_sysconfig.get_default_user().value
    default_pass = db_sysconfig.get_default_password().value
    try:
        default_user=decrypt_data(default_user)
        default_pass=decrypt_data(default_pass)
    except:
        default_user="admin"
        default_pass=""
    return default_user,default_pass

def build_api_options(dev):
    default_user,default_pass= get_default_user_pass()
    username=decrypt_data(dev.user_name ) or default_user
    password=decrypt_data(dev.password ) or default_pass
    port=dev.port or 8728
    options={
       'host':dev.ip,
       'username':username,
       'password':password,
       'routeros_version':'auto',
       'port':port,
       'ssl':False
    }
    return options

def check_device_firmware_update(dev,q):
    port=dev.port or 8728
    if check_port(dev.ip,port):
        options=build_api_options(dev)
        try:
            is_availbe , current , arch , upgrade_availble = check_update(options)
        except Exception as e:
            q.put({"id": dev.id,"update_availble":False,"reason":"Unknoown Reason"})
        if is_availbe:
                q.put({"id": dev.id,"update_availble":is_availbe,"current_firmware":current,"arch":arch,"upgrade_availble":upgrade_availble})
        else:
            if current:
                q.put({"id": dev.id,"update_availble":is_availbe,"current_firmware":current,"arch":arch,"upgrade_availble":upgrade_availble})
            else:
                q.put({"id": dev.id,"reason":"Wrong user or password"})
    else:
         q.put({"id": dev.id,"update_availble":False,"reason":"Connection problem"})

def get_interfaces_counters(router):
   result = {}
   for iface in router.api('/interface/print', stats=True):
        result[iface['name']] = iface
   return result

def get_traffic(router,interfaces):
   interfaces.append('aggregate')
   interfaces=",".join(interfaces)
   params = {'interface': interfaces, 'once': b' '}
   results = tuple(router.api('/interface/monitor-traffic', **params))
   traffic={}
   for row in results:
       traffic[row.get('name','total')]={
           'rx-packets-per-second':row.get('rx-packets-per-second',0),
           'rx-bits-per-second':row.get('rx-bits-per-second',0),
           'fp-rx-packets-per-second':row.get('fp-rx-packets-per-second',0),
           'fp-rx-bits-per-second':row.get('fp-rx-bits-per-second',0),
           'rx-drops-per-second':row.get('rx-drops-per-second',0),
           'rx-errors-per-second':row.get('rx-errors-per-second',0),
           'tx-packets-per-second':row.get('tx-packets-per-second',0),
           'tx-bits-per-second':row.get('tx-bits-per-second',0),
           'fp-tx-packets-per-second':row.get('fp-tx-packets-per-second',0),
           'fp-tx-bits-per-second':row.get('fp-tx-bits-per-second',0),
           'tx-drops-per-second':row.get('tx-drops-per-second',0),
           'tx-queue-drops-per-second':row.get('tx-queue-drops-per-second',0),
           'tx-errors-per-second':row.get('tx-errors-per-second',0),
       }
   return traffic

def get_interface_list(interfaces):
   interfaces=list(interfaces.keys())
   return interfaces

def mergeDictionary(dict_1, dict_2):
    dict_3 = {}
    keys=list(dict_1.keys())
    keys.extend(x for x in list(dict_2.keys()) if x not in keys)
    for key in keys:
        if key in dict_1 and key in dict_2:
            new_key=key
            if dict_1[key].get('default-name',False):
                if dict_1[key]['default-name']!=new_key:
                    new_key=dict_1[key].get('default-name',False)
            dict_3[new_key] = {**dict_2[key] , **dict_1[key]}
        else:
            if key in dict_1:
                dict_3[key] = {**dict_1[key]}
            else:
                dict_3[key] = {**dict_2[key]}
    return dict_3

def get_network_data(router):
   interfaces=get_interfaces_counters(router)
   interfaces_list=get_interface_list(interfaces)
   traffic=get_traffic(router,interfaces_list)
   return mergeDictionary(interfaces,traffic)

def check_or_fix_event(events,eventtype,detail,comment=False):
    if comment:
        found_event_id=next((item for item in events if item["eventtype"] == eventtype and item["detail"] == detail and comment in item["comment"]), False)        
    else:
        found_event_id=next((item for item in events if item["eventtype"] == eventtype and item["detail"] == detail), False)        
    if found_event_id:
        db_events.fix_event(found_event_id['id'])
        return True
    else:
        return False

def grab_device_data(dev, q):
    max_attempts = 3
    attempts = 0
    port=dev.port or 8728
    success = False
    time_to_wait=0.1
    while attempts < max_attempts:
        if check_port(dev.ip,port):
            success = True
            break
        attempts += 1
        time.sleep(time_to_wait)
        time_to_wait += 0.1
    if success:
        # get all device events which src is "Data Puller" and status is 0
        events=list(db_events.get_events_by_src_and_status("Data Puller", 0,dev.id).dicts())
        check_or_fix_event(events,"connection","Unreachable")
        options=build_api_options(dev)
        try:
            router=RouterOSCheckResource(options)
            _installed_version=router._get_routeros_version()
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
            call = router.api.path(
              "/system/health"
            )
            health = tuple(call)
            
            call = router.api.path(
                    "/system/identity"
                )
            name = tuple(call)
            name: Dict[str, str] = name[0]
            result.update(name)
            wireless_keys,wireless_data=[],[]
            if ISPRO:
                wireless_keys,wireless_data=utilpro.wireless_actions(router,dev,events)
            try:
                
                call = router.api.path(
                    "/interface/wireless"
                )
                wifi_results = tuple(call)
                wifi_result: Dict[str, str] = wifi_results[0]
                device_type='router'
                if wifi_result['mode'] in ['ap-bridge','bridge','wds-slave']:
                    device_type=wifi_result['mode']
                elif wifi_result['mode'] in ['station','station-wds' , 'station-pseudobridge' , 'station-pseudobridge-clone' , 'station-bridge']:
                    device_type='station'
                elif wifi_result['mode'] in  ['alignment-only','nstreme-dual-slave']:
                    device_type='special'
                else:
                    device_type='router'
            except:
                device_type='router'
        except Exception as e:
            log.error(e)
            log.warning(dev.ip)
            q.put({"id": dev.id,"detail":"API Connection","reason":e,"done":False})
            return True
        check_or_fix_event(events,"connection","API Connection")
        try:
            keys=["free-memory","cpu-load","free-hdd-space"]
            if len(health):
                #since routeros v7 they changed health res from api
                excluded_keys=['cpu-overtemp-check','active-fan','fan-mode','heater-control','psu2-state','cpu-overtemp-startup-delay','fan-on-threshold','heater-threshold','use-fan','cpu-overtemp-threshold','fan-switch','psu1-state','state','state-after-reboot']
                if 'type' in health[0]:
                    health_vals={}
                    for d in health:
                        if 'state' in d['name']:
                            if d['value'] == 'fail':
                                db_events.health_event(dev.id,'Data Puller',d['name'],'Critical',0,"{} is Failed".format(d['name']))
                            else:
                                check_or_fix_event(events,"health",d['name'])
                            continue
                        if d['name'] in excluded_keys:
                            continue
                        health_vals[d['name']]=d['value']
                else:
                    health_vals: Dict[str, str] = health[0]
                result.update(health_vals)
                keys.extend(list(health_vals.keys()))
        except Exception as e:
            log.warning(dev.ip)
            log.error(e)
            log.error(health)
            q.put({"id": dev.id,"reason":"Could not health data from device","detail":"Get Health","done":False})
            return True
        check_or_fix_event(events,"connection","Get Health")
        # ToDo remove keys without messurable value
        # keys.remove('fan-switch')
        # keys.remove('fan-on-threshold')
        try:
            # arch=result['architecture-name']
            if result['board-name']!='x86' and result["current-firmware"]==result["upgrade-firmware"]:
                dev.upgrade_availble=True
            force_syslog=True if db_sysconfig.get_sysconfig('force_syslog')=="True" else False
            force_radius=True if db_sysconfig.get_sysconfig('force_radius')=="True" else False
            if force_radius:
                try:
                    peer_ip=dev.peer_ip if dev.peer_ip else db_sysconfig.get_sysconfig('default_ip')
                    secret = db_sysconfig.get_sysconfig('rad_secret')
                    res = configure_radius(router, peer_ip,secret)
                    check_or_fix_event(events,"config","radius configuration")
                except:
                    db_events.config_event(dev.id,'Data Puller','radius configuration','Error',0,"Force radius Failed")
                    pass
            try:
                syslog_configured=check_syslog_config(dev,router,force_syslog)
                if dev.syslog_configured!=syslog_configured:
                    dev.syslog_configured=syslog_configured
                check_or_fix_event(events,"config","syslog configuration")
            except:
                db_events.config_event(dev.id,'Data Puller','syslog configuration','Error',0,"Force SysLog Failed")
                pass
            dev.current_firmware=_installed_version
            dev.uptime=result['uptime']
            dev.router_type=device_type
            if dev.name!=result['name']:
                dev.name=result['name']
            if device_type!='router':
                dev.wifi_config=json.dumps(wifi_result)

            interfaces=get_network_data(router)
            interfaces_keys=interfaces.keys()
            data={}
            for key in keys:
                if key in result:
                    data[key]=result[key]
                else:
                    data[key]=0
            for intkeys in interfaces_keys:
                keys.extend(["rx-"+intkeys,"tx-"+intkeys,"rxp-"+intkeys,"txp-"+intkeys])
                data["rx-"+intkeys]=interfaces[intkeys]['rx-bits-per-second']
                data["tx-"+intkeys]=interfaces[intkeys]['tx-bits-per-second']
                data["rxp-"+intkeys]=interfaces[intkeys]['rx-packets-per-second']
                data["txp-"+intkeys]=interfaces[intkeys]['tx-packets-per-second']
            
            if len(wireless_keys)>0:
                keys.extend(wireless_keys)
            data.update(wireless_data)
            redopts={
            "dev_id":dev.id,
            "keys":keys
            }
            reddb=RedisDB(redopts)
            if not dev.sensors or (len(json.loads(dev.sensors))<len(keys) and dev.sensors!=json.dumps(keys)):
                log.info("updating keys for device {}".format(dev.id))
                dev.sensors=json.dumps(keys)
                reddb.dev_create_keys()
            dev.save()
            reddb.add_dev_data(data)
            check_or_fix_event(events,"connection","DB Write")
        except Exception as e:
            log.error(e)
            log.warning(dev.ip)
            q.put({"id": dev.id,"reason":"Unable to store data in DB","detail":"DB Write","done":False})
            return True
    else:
        q.put({"id": dev.id, "reason":"device not reachable with port {}".format(port),"detail":"Unreachable", "done":False})
        return True
    q.put({"id": dev.id,"done":True,'data':data})
    return True


def check_syslog_config(dev,router,apply=False):
    try:
        if not router:
            options=build_api_options(dev)
            router=RouterOSCheckResource(options)
        peer_ip=dev.peer_ip if dev.peer_ip else db_sysconfig.get_sysconfig('default_ip')
        devid=dev.id
        call = router.api.path(
            "/system/logging/action"
        )
        #create syslog action 
        results = tuple(call)
        mikro1=[item for item in results if "mikrowizard" in item.get('name')]
        regex=r'^mikrowizard{}$'.format(devid)
        mikro=[item for item in mikro1 if re.match(regex,item.get('name'))]
        if len(mikro)==1 and mikro[0].get('remote-port')==5014 and mikro[0].get('remote')==peer_ip:
            action_name=mikro[0].get('name')
        else:
            if apply:
                if len(mikro1):
                    ids=[item.get('.id') for item in mikro1 if 'mikrowizard' in item.get('name')]
                    if len(ids):
                        call.remove(*ids)
                action_name='mikrowizard{}'.format(devid)
                action={
                'name':action_name, 
                'remote':peer_ip,
                'remote-port':5014,
                'target':'remote'
                }
                res=call.add(**action )
            else:
                return False

        #create loggings 
        call = router.api.path(
            "/system/logging"
        )

        results = tuple(call)

        confs=[item for item in results if action_name in item.get('action')]
        if len(confs)!=3:
            if apply:
                ids=[item.get('.id') for item in results if 'mikrowizard' in item.get('prefix')]
                log.error(ids)
                if len(ids):
                    call.remove(*ids)
                keys=['critical','error','info']
                for key in keys:
                    action={
                    'action':action_name, 
                    'topics':key,
                    'prefix':action_name,
                    }
                    res=call.add(**action )
            else:
                return False
        return True
    except Exception as e:
        log.error(e)
        return False

def apply_perm(router,name,perms):
    try:
      #check if radius client is configured and ip ,port,secret is correct
        call = router.api.path(
            "/user/group"
        )
        groups = tuple(call)
        exist=False
        for group in groups:
            if group.get('name')==name:
                exist=group.get('.id')
                p1=group.get('policy').split(',')
                p1.sort()
                if p1==perms:
                    return True
        params={
            'name':name,
            'policy':(',').join(perms)
        }
        try:
            if not exist:
                res=call.add(**params)
            else:
                params['.id']=exist
                call.update(**params)
                return True
            if res:
                return True
        except Exception as e:
            log.error(e)
            return False
    except Exception as e:
       log.error(e)
       return False

def configure_radius(router,ip,secret):
    try:
        #check if radius client is configured and ip ,port,secret is correct
        call = router.api.path(
            "/radius"
        )
        call2 = router.api.path(
            "/user/aaa"
        )
        radius = tuple(call)
        aaa = tuple(call2)
        if not aaa[0]['use-radius'] or not aaa[0]['accounting'] or not aaa[0]['interim-update']=='0s':
            params={
            'use-radius':True,
            'accounting':True,
            'interim-update':'0s'
            }
            tuple(router.api.path('user', 'aaa')('set', **params))
        for res in radius:
            if res.get('address')==ip and res.get('secret')==secret:
                return True

        #configure radius client
        action={
            'address':ip,
            'secret':secret,
            'service':'login',
            'require-message-auth':'no'
        }
        try:
            call.add(**action)
        except:
            action.pop('require-message-auth')
            call.add(**action)
        
        return True
    except Exception as e:
        log.error(e)
        return False

def FourcePermToRouter(dev,perm):
    try:
        options=build_api_options(dev)
        router=RouterOSCheckResource(options)
        peer_ip=dev.peer_ip if dev.peer_ip else db_sysconfig.get_sysconfig('default_ip')
        secret = db_sysconfig.get_sysconfig('rad_secret')
        res = configure_radius(router, peer_ip,secret)
        try:
            pl=json.loads(perm[0].perm_id.perms)
            perms=[p if pl[p] else '!{}'.format(p) for p in pl]
            perms.sort()
            _installed_version=router._get_routeros_version()
            if _installed_version > RouterOSVersion('7.6'):
                if "!dude" in perms:
                    perms.remove("!dude")
                elif "dude" in perms:
                    perms.remove("dude")
            if _installed_version > RouterOSVersion('7.2'):
                if "!tikapp" in perms:
                    perms.remove("!tikapp")
                elif "tikapp" in perms:
                    perms.remove("tikapp")
            if _installed_version < RouterOSVersion('7.1'):
                if "!rest-api" in perms:
                    perms.remove("!rest-api")
                elif "rest-api" in perms:
                    perms.remove("rest-api")
            res2=apply_perm(router,perm[0].perm_id.name,perms)
            return res2
        except Exception as e:
            log.error(e)
            pass
        return False
    except Exception as e:
        log.error(e)
        return False

def check_update(options,router=False):
    ofa=db_sysconfig.get_firmware_action().value
    #is_availbe , current , arch , data
    try:
        if not router:
            router=RouterOSCheckResource(options)
        _installed_version=router._get_routeros_version()
        try:
            if ofa=="keep" and _installed_version < RouterOSVersion('6.99.99'):
                _latest_version=RouterOSVersion(db_sysconfig.get_firmware_old().value)
            else:
                _latest_version=RouterOSVersion(db_sysconfig.get_firmware_latest().value)
        except:
            _latest_version=False
        call = router.api.path(
            "/system/resource"
        )
        results = tuple(call)
        result: Dict[str, str] = results[0]
        arch=result['architecture-name']
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
        upgrade=False
        if result['board-name']!='x86' and result['current-firmware']!= result['upgrade-firmware'] and result['board-name']!='x86':
            upgrade=True
        if _latest_version and _installed_version < _latest_version:
            return True, _installed_version,arch,upgrade
        else:
            return False, _installed_version,arch,upgrade
    except Exception as e:
        log.error("Error during firmware check for host : {}".format(options["host"]))
        log.error(e)
        return False,False,False,False

def log_alert(type,dev,massage):
    log.error("Alert: {} {} Device: {} ".format(type,massage,dev.ip))

def backup_routers(dev,q):
    status=backup_router(dev)
    q.put({"id": dev.id,"state":status})

def run_snippets(dev, snippet,q):
    result=run_snippet(dev, snippet)
    q.put({"devid": dev.id,"devip": dev.ip,"devname": dev.name, "status":True if result else False , "result":result if result else 'Exec Failed'})
    return result

def run_snippet(dev, snippet):
    port=dev.port or 8728
    try:
        if check_port(dev.ip,port):
            options=build_api_options(dev)
            options['timeout']=120
            #check ssh service status
            router=RouterOSCheckResource(options)
            options['router']=router
            call = router.api.path(
                "/ip/service"
            )
            results = tuple(call)
            ssh_info={}
            for res in results:
                if res['name'] == 'ssh':
                    ssh_info['disabled']=res['disabled']
                    ssh_info['.id']=res['.id']
                    options['ssh_port']=res['port']
                    break
            #enable ssh if disabled
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': False, '.id' : ssh_info['.id']}
                call.update(**params)
            try:
                ssh=SSH_Helper(options)
                result=ssh.exec_command(snippet)
                if not result:
                    result="executed successfully"
            except Exception as e:
                log.error(e)
                log_alert('ssh',dev,'During backup ssh error')
            if ssh_info['disabled']:
                #undo ssh config after finishing backup
                params = {'disabled': True, '.id' : ssh_info['.id']}
                call.update(**params)
            return result
        else:
            log_alert('connection',dev,'During backup error with connectiong to api')
            return False
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when connecting to ssh')
        return False

def backup_router(dev):
    port=dev.port or 8728
    try:
        if check_port(dev.ip,port):
            options=build_api_options(dev)
            options['timeout']=120
            #check ssh service status
            router=RouterOSCheckResource(options)
            options['router']=router
            call = router.api.path(
                "/ip/service"
            )
            results = tuple(call)
            ssh_info={}
            for res in results:
                if res['name'] == 'ssh':
                    ssh_info['disabled']=res['disabled']
                    ssh_info['.id']=res['.id']
                    options['ssh_port']=res['port']
                    break
            #enable ssh if disabled
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': False, '.id' : ssh_info['.id']}
                call.update(**params)
            try:
                ssh=SSH_Helper(options)
                configs=ssh.get_config()
                state=store_config(dev,configs)
                
            except Exception as e:
                log.error(e)
                log_alert('ssh',dev,'During backup ssh error')
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': True, '.id' : ssh_info['.id']}
                call.update(**params)
            return True
        else:
            log_alert('connection',dev,'During backup error with connectiong to api')
            return False
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when connecting to ssh')
        return False

def store_config(dev,configs):
    dir=config.BACKUP_DIR
    #add device mac and curent date to dir
    identifier=dev.mac
    if identifier=='tunnel':
        identifier=identifier+"_devid_"+(str(dev.id))
    dir=dir+identifier+"/"+datetime.datetime.now().strftime("%Y-%m-%d")+"/"
    filename=datetime.datetime.now().strftime("%H-%M-%S")+".txt"
    filedir=dir+filename
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        #store config file
        with open(filedir, "w") as text_file:
            text_file.write(configs)
        #add record to db
        db_backups.create(
            dev=dev,
            directory=filedir,
            size=os.path.getsize(filedir),
            )
        return True
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when saving file')
        return False

def extract_from_link(link,all_package=False):
    if all_package:
        regex = r"https:\/\/download\.mikrotik\.com\/routeros\/(\d{1,3}.*)?\/all_packages-(.*)-(.*).zip"
        matches = re.match(regex, link)
        if not matches:
            return False
        res=matches.groups()
        version=res[0]
        arch = res[1]
        return {"link":link, "arch":arch, "version":version, "all_package":True}
    else:
        regex = r"https:\/\/download\.mikrotik\.com\/routeros\/(\d{1,3}.*)?\/routeros-(.*).npk"
        matches = re.match(regex,link)
        res=matches.groups()
        version=res[0]
        arch = res[1].replace(version, "")
        if arch == "":
            arch = "x86"
        else:
            arch=arch.replace("-","")
        return {"link":link,"arch":arch, "version":version}
    

def get_mikrotik_latest_firmware_link():
    try:
        html_page = urllib.request.urlopen("https://mikrotik.com/download/")
        soup = BeautifulSoup(html_page, "html.parser")
        firms={}
        for link in soup.findAll('a'):
            link=str(link.get('href'))
            if ".npk" in link:
                frimware=extract_from_link(link)
                firms.setdefault(frimware["version"],{})
                firms[frimware["version"]][frimware["arch"]]={"link":frimware["link"],"mark":"latest"}
                # firms.append(link)
        return firms
    except Exception as e:
        log.error(e)
        return False

def get_mikrotik_download_links(version,all_package=False):
    try:
        html_page = urllib.request.urlopen("https://mikrotik.com/download/archive?v={}".format(version))
        soup = BeautifulSoup(html_page, "html.parser")
        firms={}
        for trs in soup.findAll('tr'):
            link=trs.findAll('a')
            if len(link):
                lnk=str(link[0].get('href'))
                sha=str(link[1].get('data-checksum-sha256'))
                if ".npk" in lnk:
                    frimware=extract_from_link(lnk)
                    firms.setdefault(frimware["version"], {})
                    firms[frimware["version"]][frimware["arch"]]={"link":frimware["link"],"sha":sha}
                    # firms.append(link)
                elif all_package and ".zip" in lnk:
                    frimware=extract_from_link(lnk, all_package=all_package)
                    if not frimware:
                        continue
                    firms.setdefault(frimware["version"], {})
                    firms[frimware["version"]][frimware["arch"]+"-"+"allpackage"]={"link":frimware["link"],"sha":sha}
        return firms
    except Exception as e:
        log.error(e)
        return False    

def get_mikrotik_versions():
    try:
        html_page = urllib.request.urlopen("https://mikrotik.com/download/archive")
        soup = BeautifulSoup(html_page, "html.parser")
        versions=[]
        for link in soup.findAll('a'):
            ver=link.find("strong")
            if ver:
                versions.append(ver.text)
        try:
            vers=list(get_mikrotik_latest_firmware_link().keys())
            if versions and vers:
                unique_elements = set(versions + vers)
                versions = list(unique_elements)
            elif not versions and vers:
                if vers:
                    versions = vers
        except Exception as e:
            log.error(e)
            pass
        return versions
    except Exception as e:
        log.error(e)
        return False

def check_sha256(path,sha256=False):
    hash_obj = hashlib.sha256()
    if not sha256 and os.path.exists(path):
        with open(path, 'rb') as f:
            hash_obj.update(f.read())
        return hash_obj.hexdigest()
    elif os.path.exists(path) and sha256:
        with open(path, 'rb') as f:
            hash_obj.update(f.read())
        return hash_obj.hexdigest() == sha256
    else:
        return False 

def web2file(url, filePath,sha256=False, tries=3, timeout=3, sleepBetween=1):
    tempPath = filePath
    status=False
    if os.path.exists(tempPath) and sha256:
        hash_obj = hashlib.sha256()
        with open(tempPath, 'rb') as f:
            hash_obj.update(f.read())
        if hash_obj.hexdigest() == sha256:
            log.error("File already exists : {}".format(filePath))
            return True
    failures = 0
    while True:
        tries=tries-1
        if failures == tries:
            try:
                os.remove(tempPath)
            except:
                pass
        try:
            socket.setdefaulttimeout(timeout)
            urllib.request.urlretrieve(url, tempPath)
            if sha256:
                hash_obj = hashlib.sha256()
                with open(tempPath, 'rb') as f:
                    hash_obj.update(f.read())
                if hash_obj.hexdigest() == sha256:
                    status=True
                    break
            else:
                status=True
                break
        except urllib.error.HTTPError:
            log.error("HTTP Error")
        except urllib.error.URLError:
            time.sleep(sleepBetween)
        except TimeoutError:
            pass
        except socket.timeout:
            pass
    return status
def extract_zip (file,path):
    #extract and return file names from zip file
    try:
        with zipfile.ZipFile(file, 'r') as zip_ref:
            zip_ref.extractall(path)
            names=zip_ref.namelist()
        return names
    except Exception as e:
        log.error(e)
        
def download_firmware_to_repository(version,q,arch="all",all_package=False):
    repository='/app/firms/'
    #create direcorty version in repository if not exist
    path=repository+version+"/"
    os.makedirs(path, exist_ok=True)
    # try:
    if all_package:
        #download all_packages
        links=get_mikrotik_download_links(version,all_package=all_package)
    else:
        links=get_mikrotik_download_links(version)
    if links:
        links=links[version]
        log.error(links)
        firm=db_firmware.Firmware()
        for lnk in links:
            if all_package and arch+"-allpackage" == lnk:
                arch_togo=lnk
                link=links[lnk]["link"]
                sha256=links[lnk]["sha"]
                file=path+"all_packages-" + arch + ".zip"
                log.error(link)
                done=web2file(link, file, sha256=sha256)
                files=extract_zip(file, path)
                log.error(files)
                try:
                    if done and len(files)>0:
                        for f in files:
                            file=path+f
                            log.error(file)
                            sha256=check_sha256(file)
                            firm.insert(version=version, location=file, architecture=arch+"-"+f.split("-")[0], sha256=sha256).on_conflict(conflict_target=['version', 'architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status":True})
                # return True
            if arch!="all" and arch==lnk:
                arch_togo=lnk
                link=links[lnk]["link"]
                log.error(arch)
                log.error(link)
                sha256=links[lnk]["sha"]
                file=path+"{}.npk".format(arch)
                done=web2file(link, file,sha256=sha256)
                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version','architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status":True})
                # return True
            if arch=="all":
                #download file to path and check sha265 
                arch_togo=lnk
                link=links[lnk]["link"]
                sha256=links[lnk]["sha"]
                file=path+"{}.npk".format(arch)
                done=web2file(link, file,sha256=sha256)
                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version','architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
        if q:
            q.put({"status":True})
        return True
    else:
        if q:
            q.put({"status":False})
        return False
    # except Exception as e:
    #     log.error(e)
    #     if q:
    #         q.put({"status":True})
    #     return False


def update_device(dev,q):
    events=list(db_events.get_events_by_src_and_status("updater", 0,dev.id).dicts())
    ofa=db_sysconfig.get_firmware_action().value
    _installed_version=RouterOSVersion(dev.current_firmware)
    try:
        if dev.firmware_to_install:
            ver_to_install=dev.firmware_to_install
        elif ofa=="keep" and _installed_version < RouterOSVersion('7.0.0'):
            ver_to_install=db_sysconfig.get_firmware_old().value
        else:
            ver_to_install=db_sysconfig.get_firmware_latest().value
        ver_to_install = RouterOSVersion(ver_to_install)
    except Exception as e:
        log.error(e)
        q.put({"id": dev.id})
        return False
    arch=dev.arch
    if not dev.firmware_to_install or RouterOSVersion(dev.firmware_to_install)!=ver_to_install:
        dev.firmware_to_install=ver_to_install
        dev.save()
    try:
        if _installed_version==ver_to_install:
            check_or_fix_event(events,"firmware","Update Failed")
            check_or_fix_event(events,"firmware","Firmware repositpry")
            check_or_fix_event(events,"firmware","Device storage")
            dev.failed_attempt=0
            dev.firmware_to_install=None
            dev.save()
            q.put({"id": dev.id})
            return True
    except Exception as e:
        log.error(e)
        pass
    #get correct firmware from db for updating
    firm=False
    if ISPRO:
        firm=utilpro.safe_check(dev,_installed_version,ver_to_install)
    elif arch and arch!='':
        firm=db_firmware.get_frim_by_version(ver_to_install, arch)
    else:
        q.put({"id": dev.id})
    if firm and firm.architecture == arch:
        dev.failed_attempt=dev.failed_attempt+1
        if dev.failed_attempt > 3:
            db_events.firmware_event(dev.id,"updater","Update Failed","Critical",0,"Unable to Update device")
        dev.status="updating"
        dev.save()
        options=build_api_options(dev)
        try:
            url=db_sysconfig.get_sysconfig('system_url')
            url=url+"/api/firmware/get_firmware/{}".format(firm.id)
            router=RouterOSCheckResource(options)
            api = router._connect_api()
            params = {"url": url,"keep-result":"yes","dst-path":arch+".npk"}
            cmd='/tool/fetch'
            call = api(cmd,**params)
            results = tuple(call)
            result: Dict[str, str] = results[-1]
            if result['status'] == 'finished':
                check_or_fix_event(events,"firmware","Device storage")
                cmd='/system/reboot'
                call = api(cmd)
                rebootresults = tuple(call)
                if len(rebootresults)==0:
                    check_or_fix_event(events,"firmware","Firmware repositpry")
                    dev.status="updated"
                    dev.save()
                else:
                    dev.status="failed"
                    dev.save()
            else:
                db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"There is a problem with downloadin of Firmware in device")
                dev.status="failed"
                dev.save()
        except Exception as e:
            dev.status="failed"
            dev.save()
            if 'no space left' in str(e):
                db_events.firmware_event(dev.id,"updater","Device storage","Error",0,"There is not enogh space in device storage")
            if '404 Not Found' in str(e):
                db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"Firmware not found #1 :Please check firmware config in settings section")
            log.error(e)
            q.put({"id": dev.id})
    else:
        db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"Firmware not found #2 :Please check firmware config in settings section")
        log.error('No Firmware found for device {}({})'.format(dev.name,dev.ip))
    q.put({"id": dev.id})

def get_ethernet_wifi_interfaces():
    interfaces = netifaces.interfaces()
    ethernet_wifi_interfaces = []
    interfaces.sort()
    for interface in interfaces:
        try:
            addr = netifaces.ifaddresses(interface)
            if 17 in addr.keys():
                if re.match(r'(en|wl|eth).*',interface):
                    ethernet_wifi_interfaces.append({'interface':interface
                                                     ,'mac':addr[17][0]['addr']})
        except Exception as e:
            log.error(e)
            pass
    return ethernet_wifi_interfaces

def generate_serial_number(interfaces):
    mac_addresses = []
    for interface in interfaces:
        try:
            mac_addresses.append(interface['mac'])
        except Exception as e:
            pass
    if len(mac_addresses)>0:
        # Sort the MAC addresses to ensure consistent ordering
        mac_addresses.sort()
        # Concatenate the MAC addresses into a single string
        mac_string = ''.join(mac_addresses)
        # Generate a UUID based on the MAC string
        hwid = "mw" +  str(uuid.uuid5(uuid.NAMESPACE_DNS, mac_string))
        return str(hwid)
    else:
        return None

def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def get_local_users(opts):
    try:
        router=RouterOSCheckResource(opts)
        call = router.api.path(
            "/user"
        )
        results=[a['name'] for a in  tuple(call)]
        return results
    except Exception as e:
        log.error(e)
        return False

def ispro():
    return ISPRO

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)

