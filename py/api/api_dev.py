#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_bakcups.py: API for managing bakcups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request,redirect ,session
import datetime
import html

import config
import re
from libs.red import RedisDB
from libs.webutil import app,buildResponse,login_required,get_myself,get_ip,get_agent
from libs import util
from libs.db import db_device,db_groups,db_user_group_perm,db_user_tasks,db_sysconfig,db_syslog
import logging
import json
from playhouse.shortcuts import model_to_dict
log = logging.getLogger("api")
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

@app.route('/', methods = ['GET'])
def index():
    """Just a redirect to api list."""
    if config.IS_PRODUCTION:
        return "not available", 400
    return redirect('/api/list')

@app.route('/api/dev/list', methods = ['POST'])
@login_required(role='admin',perm={'device':'read'})
def list_devs():
    """Return devs list of assigned to user , all for admin"""
    input = request.json
    # Get devices that are in the group
    group_id = int(input.get('group_id', False))
    page = input.get('page')
    size = input.get('size')
    search = input.get('search',False)
    page = int(page or 0)
    limit = int(size or 1000)
    res = []
    try:
        # Get devices that current user have access
        uid = session.get("userid") or False
        if not uid:
            return buildResponse({'result':'failed','err':"No User"}, 200)
        # Get devices that current user have access
        devs=db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid,group_id).paginate(page, limit).dicts()
        for dev in devs:
            temp=dev
            del temp['user_name']
            del temp['password']
            if ' ' not in temp['uptime']:
                temp['uptime'] = temp['uptime'].replace('w',' week ').replace('d',' day ').replace('h',' hour ').replace('m',' min ')
            res.append(temp)
    except Exception as e:
        return buildResponse({'result':'failed','err':str(e)},200)
    return buildResponse(res,200)

@app.route('/api/dev/get_editform', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def get_editform():
    """return device editable data"""
    input = request.json
    # get devices that are in the group
    devid = int(input.get('devid', False))
    res = {}
    try:
        dev=db_device.get_device(devid)
        if not dev:        
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        res['user_name']=util.decrypt_data(dev['user_name'])
        res['password']=util.decrypt_data(dev['password'])
        res['ip']=dev['ip']
        res['peer_ip']=dev['peer_ip']
        res['name']=dev['name']
        res['id']=dev['id']
        try:
            res['ips']=json.loads(db_sysconfig.get_sysconfig('all_ip'))
        except Exception as e:
            res['ips']=[]
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
    return buildResponse(res,200)

@app.route('/api/dev/save_editform', methods = ['POST'])
@login_required(role='admin', perm={'device':'full'})
def save_editform():
    """save device configuration"""
    input = request.json
    devid = int(input.get('id', False))
    user_name = input.get('user_name', False)
    password = input.get('password', False)
    ip = input.get('ip', False)
    peer_ip = input.get('peer_ip', False)
    name = input.get('name', False)
    try:
        if db_device.update_device(devid, util.crypt_data(user_name), util.crypt_data(password), ip, peer_ip, name):
            db_syslog.add_syslog_event(get_myself(), "Device", "Edit", get_ip(),get_agent(),json.dumps(input))
            return buildResponse({"result":"success"}, 200)
        else:
            return buildResponse({"result":"failed","err":"Unable to update device"}, 200)
    except Exception as e:
        log.error(e)
        return buildResponse({"result":"failed","err":str(e)}, 200)


@app.route('/api/devgroup/list', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'read'})
def list_devgroups():
    """return dev groups"""
    
    # build HTML of the method list
    devs = []
    try:
        devs=list(db_groups.query_groups_api())
    except Exception as e:
        return buildResponse({'result':'failed','err':str(e)},200)
    return buildResponse(devs,200)

@app.route('/api/devgroup/delete', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'full'})
def delete_group():
    """delete dev group"""
    input = request.json
    gid = input.get('gid', False)
    try:
        if db_user_group_perm.DevUserGroupPermRel.delete_group(gid):
            db_syslog.add_syslog_event(get_myself(), "Device Group","Delete", get_ip(),get_agent(),json.dumps(input))
            return buildResponse({"result":"success"}, 200)
        else:
            return buildResponse({"result":"failed",'err':'Unable to delete'}, 200)
    except Exception as e:
        return buildResponse({"result":"failed",'err':'Unable to delete'}, 200)


@app.route('/api/devgroup/members', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'read','device':'read'})
def list_devgroups_members():
    """return list of dev groups"""
    input = request.json
    gid=input.get('gid',False)
    # get devices that are in the group
    devs = []
    try:
        devs=list(db_groups.devs(gid))
    except Exception as e:
        return buildResponse({'result':'failed','err':str(e)},200)
    return buildResponse(devs,200)

@app.route('/api/devgroup/update_save_group', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'write','device':'read'})
def update_save_group():
    """save device group config"""
    input = request.json
    devids= input.get('array_agg', False)
    name = input.get('name', False)
    id = input.get('id', False)

    # First check if we are editiong or creating new group
    # if id is 0 then we are creating new group
    
    if id==0:
        # create new group and add devices to it
        try:
            group=db_groups.create_group(name)
            if group:
                db_syslog.add_syslog_event(get_myself(), "Device Group","Create", get_ip(),get_agent(),json.dumps(input))
                gid=group.id
                db_groups.add_devices_to_group(gid,devids)
            else:
                return buildResponse({'result':'failed','err':"Group not created"}, 200)
            return buildResponse({"result":"success"}, 200)
        except Exception as e:
            return buildResponse({'result':'failed','err':str(e)}, 200)
    else:
        # update group and add devices to it
        try:
            group=db_groups.update_group(id, name)
            db_groups.add_devices_to_group(group.id, devids)
            #get all dev ids from group and compare to devids,remove devs not availble in devids
            devs=db_groups.devs2(id)
            ids=[]
            for dev in devs:
                ids.append(dev.id)
            dev_to_remove=list(set(ids)-set(devids))
            db_groups.delete_from_group(dev_to_remove)
            db_syslog.add_syslog_event(get_myself(), "Device Group","Update", get_ip(),get_agent(),json.dumps(input))
            return buildResponse({"result":"success"}, 200)
        except Exception as e:
            return buildResponse({'result':'failed','err':str(e)}, 200)


@app.route('/api/search/groups', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'read','device':'read'})
def search_groups():
    """search in devices"""
    input = request.json
    searchstr=input.get('searchstr',False)
    dev_groups = []
    group=db_groups.DevGroups
    try:
        if searchstr and searchstr!="":
            # find device groups  that contains searchstr in the name
            dev_groups = (group
                        .select()
                        .where(group.name.contains(searchstr))
                        .dicts())
        else:
            # return first 10 ordered alphabeticaly
            dev_groups = (group
                        .select()
                        .order_by(group.name)
                        .limit(10)
                        .dicts())
    except Exception as e:
        return buildResponse({'result':'failed','err':str(e)},200)
    return buildResponse(dev_groups,200)

@app.route('/api/search/devices', methods = ['POST'])
@login_required(role='admin',perm={'device':'read'})
def search_devices():
    """search in groups"""
    input = request.json
    searchstr=input.get('searchstr',False)
    # build HTML of the method list
    device=db_device.Devices
    searchstr=input.get('searchstr',False)
    devs = []
    try:
        if searchstr and searchstr!="":
            # find devices that contains searchstr in the name
            devs = (device
                    .select()
                    .where(device.name.contains(searchstr))
                    .dicts())
        else:
            # return first 10 ordered alphabeticaly
            devs = (device
                    .select()
                    .order_by(device.name)
                    .limit(10)
                    .dicts())
    except Exception as e:
        return buildResponse({'result':'failed','err':str(e)},200)
    return buildResponse(devs,200)


@app.route('/api/taskmember/details', methods = ['POST'])
@login_required(role='admin',perm={'device_group':'read','device':'read'})
def get_taskmember_details():
    """search in groups"""
    # build HTML of the method list
    input = request.json
    tid=input.get('taskid',False)
    if not tid:
        return buildResponse({"success":'failed',"err":"Wrong task"},200)
    res=[]
    utask=db_user_tasks.UserTasks.get_utask_by_id(tid)
    members=db_user_tasks.get_task_devices(utask,False)
    if utask.selection_type=="groups":
        for group in members:
            tmp = model_to_dict(group)
            res.append({"id":tmp['id'], "name":tmp['name']})
    else:
        for dev in members:
            tmp = model_to_dict(dev)
            res.append({"id":tmp['id'],"name":tmp['name'],"mac":tmp['mac']})
    return buildResponse(res,200)


@app.route('/api/dev/info', methods = ['POST'])
@login_required(role='admin',perm={'device':'read'})
def dev_info():
    """return dev info"""
    input = request.json
    devid=input.get('devid',False)
    if not devid or not isinstance(devid, int):
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    res=db_device.get_device(devid)
    options=util.build_api_options(db_device.get_devices_by_id([res['id'],])[0])
    network_info=[]
    try:
        if util.check_port(options['host'],options['port']):
            router=util.RouterOSCheckResource(options)
            network_info=util.get_network_data(router)
            del network_info['total']
    except:
        pass
    interfaces=[]
    for iface in network_info:
        interfaces.append(network_info[iface])
    #fix and change some data
    res['interfaces']=interfaces
    res.pop('user_name')
    res.pop('password')
    res.pop('wifi_config')
    res['created']=res['created'].strftime("%Y-%m-%d %H:%M:%S")
    res['modified']=res['modified'].strftime("%Y-%m-%d %H:%M:%S")
    #get data from redis
    if ISPRO:
        res['is_radio']=utilpro.check_is_radio(res['id'])
    try:
        del res['sensors']
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        pass
    return buildResponse(res,200)

@app.route('/api/dev/sensors', methods = ['POST'])
@login_required(role='admin',perm={'device':'read'})
def dev_sensors():
    """return dev sensors chart data"""
    input = request.json
    devid=input.get('devid',False)
    total=input.get('total','bps')
    delta=input.get('delta',"5m")
    if delta not in ["5m","1h","daily","live"]:
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    if not devid or not isinstance(devid, int):
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    dev=db_device.get_device(devid)
    if delta=="5m":
        start_time=datetime.datetime.now()-datetime.timedelta(minutes=5*24)
    elif delta=="1h":
        start_time=datetime.datetime.now()-datetime.timedelta(hours=24)
    elif delta=="daily":
        start_time=datetime.datetime.now()-datetime.timedelta(days=30)
    else:
        start_time=datetime.datetime.now()-datetime.timedelta(days=30)
    end_time=datetime.datetime.now()
    try:
        res={}
        res['sensors']=json.loads(dev['sensors'])
        redopts={
            "dev_id":dev['id'],
            "keys":res['sensors'],
            "start_time":start_time,
            "end_time":end_time,
            "delta":delta,
        }
        colors={
            'backgroundColor': 'rgba(77,189,116,.2)',
            'borderColor': '#4dbd74',
            'pointHoverBackgroundColor': '#fff'
        }
        reddb=RedisDB(redopts)
        data=reddb.get_dev_data_keys()
        tz=db_sysconfig.get_sysconfig('timezone')
        res["radio-sensors"]=[]
        for key in res['sensors'][:]:
            if "rx" in key or "tx" in key or "rxp" in key or "txp" in key or "radio" in key:
                if "radio" in key:
                    res["radio-sensors"].append(key)
                if not 'total' in key:
                    res['sensors'].remove(key)
                    continue
            if "total" in key:
                if total=='bps' and 'rx/tx-total' in res['sensors'] and 'rx/tx-total' in res['sensors']:
                    continue
                if total!='bps' and 'rxp/txp-total' in res['sensors'] and 'rxp/txp-total' in res['sensors']:
                    continue
                temp=[]
                ids=['yA','yB']
                colors=['#17522f','#171951']

                datasets=[]
                lables=[]
                data_keys=['tx-total','rx-total']
                if total!='bps':
                    data_keys=['txp-total','rxp-total']
                for idx, val in enumerate(data_keys)  :
                    for d in data[val]:
                        if len(lables) <= len(data[val]):
                            edatetime=datetime.datetime.fromtimestamp(d[0]/1000)
                            lables.append(util.utc2local(edatetime,tz=tz).strftime("%m/%d/%Y, %H:%M:%S %Z"))
                        temp.append(round(d[1],1))
                    datasets.append({'borderColor': colors[idx],'type': 'line','yAxisID': ids[idx],'data':temp,'unit':val.split("-")[0],'backgroundColor': colors[idx],'pointHoverBackgroundColor': '#fff'})
                    temp=[]
                
                if total=='bps':
                    res["rx/tx-total"]={'labels':lables,'datasets':datasets}
                    res['sensors'].append("rx/tx-total")
                else:
                    res["rxp/txp-total"]={'labels':lables,'datasets':datasets}
                    res['sensors'].append("rxp/txp-total")

            else:
                temp={"labels":[],"data":[]}
                for d in data[key]:
                    edatetime=datetime.datetime.fromtimestamp(d[0]/1000)
                    temp["labels"].append(util.utc2local(edatetime,tz=tz).strftime("%m/%d/%Y, %H:%M:%S %Z"))
                    temp["data"].append(round(d[1],1))
                res[key]={'labels':temp["labels"],'datasets':[{'data':temp['data'],'backgroundColor': 'rgba(77,189,116,.2)','borderColor': '#fff','pointHoverBackgroundColor': '#fff'}]}
            if 'rxp-total' in res['sensors']:
                res['sensors'].remove('txp-total')
                res['sensors'].remove('rxp-total')
            elif 'rx-total' in res['sensors']:
                res['sensors'].remove('tx-total')
                res['sensors'].remove('rx-total')
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error="Error in generating data")
        pass
    return buildResponse(res,200)



@app.route('/api/dev/ifstat', methods = ['POST'])
@login_required(role='admin',perm={'device':'read'})
def dev_ifstat():
    """return device interfaces info"""
    input = request.json
    devid=input.get('devid',False)
    chart_type=input.get('type','bps')
    delta=input.get('delta',"5m")
    interface=input.get('interface',False)
    if delta not in ["5m","1h","daily","live"]:
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    if not devid or not isinstance(devid, int):
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    res=db_device.get_device(devid)
    if delta=="5m":
        start_time=datetime.datetime.now()-datetime.timedelta(minutes=5*24)
    elif delta=="1h":
        start_time=datetime.datetime.now()-datetime.timedelta(hours=24)
    elif delta=="daily":
        start_time=datetime.datetime.now()-datetime.timedelta(days=30)
    else:
        start_time=datetime.datetime.now()-datetime.timedelta(days=30)
    
    end_time=datetime.datetime.now()
    #Fix and change some data
    #Get data from redis
    res['name']="Device : " + db_device.get_device(devid)['name'] + " - Interface : " + interface
    try:
        res['sensors']=json.loads(res['sensors'])
        for sensor in res['sensors'][:]:
            regex=r'.*{}$'.format(interface)
            if not bool(re.match(regex,sensor)):
                res['sensors'].remove(sensor)
        redopts={
            "dev_id":res['id'],
            "keys":res['sensors'],
            "start_time":start_time,
            "end_time":end_time,
            "delta":delta,
        }
        colors={
            'backgroundColor': 'rgba(77,189,116,.2)',
            'borderColor': '#4dbd74',
            'pointHoverBackgroundColor': '#fff'
        }
        reddb=RedisDB(redopts)
        data=reddb.get_dev_data_keys()

        temp=[]
        ids=['yA','yB']
        colors=['#17522f','#171951']

        datasets=[]
        lables=[]
        tz=db_sysconfig.get_sysconfig('timezone')
        data_keys=['tx-{}'.format(interface),'rx-{}'.format(interface)]
        if chart_type=='bps':
            data_keys=['tx-{}'.format(interface),'rx-{}'.format(interface)]
        elif chart_type=='pps':
            data_keys=['txp-{}'.format(interface),'rxp-{}'.format(interface)]
        for idx, val in enumerate(data_keys):
            for d in data[val]:
                if len(lables) <= len(data[val]):
                    edatetime=datetime.datetime.fromtimestamp(d[0]/1000)
                    lables.append(util.utc2local(edatetime,tz=tz).strftime("%m/%d/%Y, %H:%M:%S %Z"))
                temp.append(round(d[1],1))
            datasets.append({'label':val,'borderColor': colors[idx],'type': 'line','yAxisID': ids[idx],'data':temp,'unit':val.split("-")[0],'backgroundColor': colors[idx],'pointHoverBackgroundColor': '#fff'})
            temp=[]
        res["data"]={'labels':lables,'datasets':datasets}
        
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error="Error in generating data")
        pass
    return buildResponse(res,200)

@app.route('/api/dev/delete', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def dev_delete():
    """return dev info"""
    input = request.json
    devids=input.get('devids', False)
    res={}
    # ToDo: we need to delete redis keys also
    try:
        for dev in devids:
            if db_groups.delete_device(dev):
                db_syslog.add_syslog_event(get_myself(), "Device","Delete", get_ip(),get_agent(),json.dumps(input))
                res['status']='success'
            else:
                res['status'] = 'failed'
                res['err'] = 'Unable to Delete Device'
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error=str(e))
    return buildResponse(res, 200)

#Development tool , We dont want this in production
@app.route('/api/list', methods = ['GET'])
def list_api():
    """List the available REST APIs in this service as HTML. Queries
    methods directly from Flask, no need to maintain separate API doc.
    (Maybe this could be used as a start to generate Swagger API spec too.)"""

    # decide whether available in production
    if config.IS_PRODUCTION:
        return "not available in production", 400

    # build HTML of the method list
    apilist = []
    rules = sorted(app.url_map.iter_rules(), key=lambda x: str(x))
    for rule in rules:
        f = app.view_functions[rule.endpoint]
        docs = f.__doc__ or ''
        module = f.__module__ + ".py"

        # remove noisy OPTIONS
        methods = sorted([x for x in rule.methods if x != "OPTIONS"])
        url = html.escape(str(rule))
        if not "/api/" in url and not "/auth/" in url:
            continue
        apilist.append("<div><a href='{}'><b>{}</b></a> {}<br/>{} <i>{}</i></div>".format(
            url, url, methods, docs, module))

    header = """<body>
        <title>MikroWizard Generated API LIST</title>
        <style>
            body { width: 80%; margin: 20px auto;
                 font-family: Courier; }
            section { background: #eee; padding: 40px 20px;
                border: 1px dashed #aaa; }
            i { color: #888; }
        </style>"""
    title = """
        <section>
        <h2>REST API ({} end-points)</h2>
        <h3>IS_PRODUCTION={}  IS_LOCAL_DEV={} Started ago={}</h3>
        """.format(len(apilist), config.IS_PRODUCTION, config.IS_LOCAL_DEV,
                config.started_ago(True))
    footer = "</section></body>"

    return header + title + "<br/>".join(apilist) + footer
