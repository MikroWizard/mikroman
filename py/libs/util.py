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
from libs.db import db_sysconfig,db_backups,db_events
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
import netifaces

log = logging.getLogger("util")
try:
    from libs import utilpro
    from libs import neighbour_pro as neighbour
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
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
            try:
                call = router.api.path(
                  "/system/health"
                )
                health = tuple(call)
            except Exception as e:
                log.warning("Failed to fetch /system/health for {}: {}".format(dev.ip, e))
                health = ()
            
            call = router.api.path(
                    "/system/identity"
                )
            name = tuple(call)
            name: Dict[str, str] = name[0]
            result.update(name)
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
                
                health_vals={}
                # Normalize health data to a dictionary
                # v7 format: [{'name': 'voltage', 'value': '24.1', 'type': 'V'}, ...]
                # v6 format: [{'voltage': '24.1', 'temperature': '30'}]
                
                # Check for v7 format
                is_v7_format = False
                if isinstance(health[0], dict) and 'name' in health[0] and 'value' in health[0]:
                    is_v7_format = True
                
                items_to_process = []
                if is_v7_format:
                    for item in health:
                        if 'name' in item and 'value' in item:
                             items_to_process.append((item['name'], item['value']))
                else:
                    # v6 format or single dict
                    for item in health:
                        for k, v in item.items():
                            items_to_process.append((k, v))

                for name, value in items_to_process:
                    if 'state' in name:
                        if value == 'fail':
                             db_events.health_event(dev.id,'Data Puller',name,'Critical',0,"{} is Failed".format(name))
                        else:
                             check_or_fix_event(events,"health",name)
                        # Don't add state to health_vals (Redis)
                        continue
                    
                    if name in excluded_keys:
                        continue

                    # Validate and convert value for Redis
                    try:
                        # 1. Strip units (e.g. "12.1V", "50C", "1547mA")
                        # Remove trailing letters/percents
                        val_clean = re.sub(r'[a-zA-Z%]+$', '', str(value)).strip()
                        
                        # 2. Convert to float
                        val = float(val_clean)
                        
                        # 3. Round to 2 decimal places
                        val = round(val, 2)
                        
                        health_vals[name] = val
                    except (ValueError, TypeError):
                        # Skip if conversion fails (e.g. ranges "50-55", strings "ok", "manual")
                        continue

                result.update(health_vals)
                keys.extend(list(health_vals.keys()))
        except Exception as e:
            log.warning(dev.ip)
            log.error(e)
            log.error(health)
            q.put({"id": dev.id,"reason":"Could not health data from device","detail":"Get Health","done":False})
            return True
        check_or_fix_event(events,"connection","Get Health")
        try:
            # arch=result['architecture-name']
            try:
                is_availbe , current , arch , upgrade_availble = check_update(options)
                dev.update_availble=is_availbe
                dev.upgrade_availble=upgrade_availble
                dev.current_firmware=current
            except:
                pass
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
            wireless_keys,wireless_data=[],[]
            neighbours=[]
            if ISPRO:
                try:
                   neighbour.get_neighbors(router,result,interfaces,dev.id)
                #show traceback of error
                except Exception as e:
                    #show traceback
                    log.error(f"Error: {e}")
                try:
                    wireless_keys,wireless_data=utilpro.wireless_actions(router,dev,events)
                except Exception as e:
                    log.error(e)
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
        if 'x86' not in arch and result['current-firmware']!= result['upgrade-firmware'] and result['board-name']!='x86':
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
    q.put({"id": dev.id,"devip":dev.ip,"state":status})

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
                if "no such item" in result:
                    result=False
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

def get_local_users(opts,router=False,full=False):
    try:
        if not router:
            router=RouterOSCheckResource(opts)
        call = router.api.path(
            "/user"
        )
        if not full:
            results=[a['name'] for a in  tuple(call)]
        else:
            results=tuple(call)
        return results
    except Exception as e:
        log.error(e)
        return False

def delete_file(file):
    try:
        #check if file exist:
        if not os.path.exists(file):
            return True
        os.remove(file)
        return True
    except Exception as e:
        log.error(e)
        return False
def ispro():
    return ISPRO

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

