#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_firmware.py: API for managing logs and dashboard data
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request
import datetime

from libs.db import db,db_syslog,db_device,db_AA,db_events,db_sysconfig
from libs.webutil import app,buildResponse,login_required
import logging
import operator
from libs import util
from functools import reduce
from libs.red import RedisDB
import feedparser
import requests
import json

log = logging.getLogger("logs")

def peewee_sql_to_str(sql):
    return (sql[0] % tuple(sql[1]))

@app.route('/api/auth/list', methods = ['POST'])
@login_required(role='admin',perm={'authentication':'read'})
def list_auth_log():
    """return all authentication data (default last 24H)"""
    input = request.json
    start_time=input.get('start_time',False)
    end_time=input.get('end_time',False)
    ip=input.get('ip',False)
    devip=input.get('devip',False)
    devid=input.get('devid',False)
    username=input.get('user',False)
    ltype=input.get('state',False)
    server=input.get('server',False)
    by=input.get('connection_type',False)
    auth=db_AA.Auth
    # build where query
    clauses = []
    if ip and ip != "":
        clauses.append(auth.ip.contains(ip))
    if username and username !="":
        clauses.append(auth.username.contains(username))
    if ltype and ltype!='All':
        clauses.append(auth.ltype == ltype)
    if by and by !='All':
        clauses.append(auth.by == by)
    if devid and devid>0:
        clauses.append(auth.devid == devid)
    if start_time:
        start_time=start_time.split(".000Z")[0]
        start_time=datetime.datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(auth.created >= start_time)
    else:
        #set start time to one day ago
        start_time=datetime.datetime.now()-datetime.timedelta(days=1)
        clauses.append(auth.created >= start_time)
    if end_time:
        end_time=end_time.split(".000Z")[0]
        end_time=datetime.datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(auth.created <= end_time)
    else:
        end_time=datetime.datetime.now()
        clauses.append(auth.created<=end_time)
    if server and server !="All":
        if server=='Local':
            clauses.append(auth.sessionid.is_null(True))
        else:
            clauses.append(auth.sessionid.is_null(False))
    expr=""
    devs=db_device.Devices
    if devip and devip!="":
        clauses.append(devs.ip.contains(devip))
    logs = []
    selector=[auth.ip,auth.username,auth.started,auth.ended,auth.sessionid,auth.ltype,auth.by,auth.message,auth.created,devs.ip.alias('devip'),devs.name]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=auth.select(*selector).join(devs).where(expr)
        else:
            query=auth.select(*selector).join(devs)
        query=query.order_by(auth.id.desc())
        logs=list(query.dicts())
    except Exception as e:
        return buildResponse({"status":"failed", "err":str(e)},200)
    return buildResponse(logs,200)

@app.route('/api/account/list', methods = ['POST'])
@login_required(role='admin',perm={'accounting':'read'})
def list_account_log():
    """return all accounting data (default last 24H)"""
    input = request.json
    devid=input.get('devid',False)
    username=input.get('user',False)
    action=input.get('action',False)
    section=input.get('section',False)
    message=input.get('message',False)
    start_time=input.get('start_time',False)
    end_time=input.get('end_time',False)
    config=input.get('config',False)
    ip=input.get('ip',False)
    acc=db_AA.Account
    # build where query
    clauses = []
    clauses.append(acc.username!="unknown")
    if action and action!='All':
        clauses.append(acc.action.contains(action))
    if username:
        clauses.append(acc.username.contains(username))
    if section and section!='All':
        clauses.append(acc.section.contains(section))
    if message:
        clauses.append(acc.message.contains(message))
    if start_time:
        start_time=start_time.split(".000Z")[0]
        start_time=datetime.datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(acc.created >= start_time)
    else:
        #set start time to one day ago
        start_time=datetime.datetime.now()-datetime.timedelta(days=1)
        clauses.append(acc.created >= start_time)
    if devid and devid>0:
        clauses.append(acc.devid == devid)
    if end_time:
        end_time=end_time.split(".000Z")[0]
        end_time=datetime.datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(acc.created <= end_time)
    else:
        end_time=datetime.datetime.now()
        clauses.append(acc.created<=end_time)
    if config and config!="":
        clauses.append(acc.config.contains(config))
    expr=""
    devs=db_device.Devices
    if ip and ip!="":
        clauses.append(devs.ip.contains(ip))
    logs = []
    selector=[acc.action,acc.username,acc.ctype,acc.address,acc.config,acc.section,acc.message,acc.created,devs.ip.alias('devip'),devs.name]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=acc.select(*selector).join(devs).where(expr)
        else:
            query=acc.select(*selector).join(devs)
        query=query.order_by(acc.id.desc())
        logs=list(query.dicts())
    except Exception as e:
        return buildResponse({"status":"failed", "err":str(e)},200)
    return buildResponse(logs,200)



@app.route('/api/devlogs/list', methods = ['POST'])
@login_required(role='admin', perm={'device':'read'})
def dev_events_list():
    """return Device Events"""
    input = request.json
    devid=input.get('devid',False)
    event_start_time=input.get('start_time',False)
    event_end_time=input.get('end_time',False)
    event_type=input.get('event_type',False)
    status=input.get('status',"All")
    level=input.get('level',False)
    detail=input.get('detail',False)
    comment=input.get('comment',False)
    src=input.get('src', False)
    
    event=db_events.Events
    # build where query
    clauses = []
    clauses2 = []
    if event_start_time:
        event_start_time=event_start_time.split(".000Z")[0]
        event_start_time=datetime.datetime.strptime(event_start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(event.eventtime >= event_start_time)
    else:
        clauses.append(event.eventtime >= datetime.datetime.now()-datetime.timedelta(days=1))
    if event_end_time:
        event_end_time=event_end_time.split(".000Z")[0]
        event_end_time=datetime.datetime.strptime(event_end_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(event.eventtime <= event_end_time)
    else:
        clauses.append(event.eventtime <= datetime.datetime.now())
    if event_type:
        clauses.append(event.eventtype == event_type)
    if status!="all":
        clauses.append(event.status == status)
    if level and level!='All':
        clauses.append(event.level == level)
    if detail:
        for d in detail:
            clauses2.append(event.detail.contains(d))
        # clauses.append(event.detail.contains(detail))
    if comment:
        clauses.append(event.comment.contains(comment))
    if src:
        clauses.append(event.src == src)
    if devid:
        dev=db_device.get_device(devid)
        if not dev:
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        else:
            clauses.append(event.devid == devid)
    expr=""
    devs=db_device.Devices
    events=[]
    selector=[event.eventtime,event.eventtype,event.fixtime,event.status,event.level,event.detail,event.comment,event.src,event.id,devs.ip.alias('devip'),devs.name,devs.mac]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=event.select(*selector).join(devs).where(expr)
            if len(clauses2):
                expr2 = reduce(operator.or_, clauses2)
                query=query.where(expr2)
        else:
            query=event.select(*selector).join(devs)
        query=query.order_by(event.id.desc())
        events=list(query.dicts())
    except Exception as e:
        log.error(e)
        return buildResponse({"status":"failed", "err":str(e)}, 200)
    return buildResponse(events, 200)


@app.route('/api/syslog/list', methods = ['POST'])
@login_required(role='admin', perm={'settings':'read'})
def syslog_list():
    """return MikroWizard innternal syslog"""
    input = request.json
    userid=input.get('userid',False)
    event_start_time=input.get('start_time',False)
    event_end_time=input.get('end_time',False)
    action=input.get('action',False)
    section=input.get('section',False)
    ip=input.get('ip',False)
    syslog=db_syslog.SysLog
    # build where query
    clauses = []
    if event_start_time:
        event_start_time=event_start_time.split(".000Z")[0]
        event_start_time=datetime.datetime.strptime(event_start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(syslog.created >= event_start_time)
    else:
        clauses.append(syslog.created >= datetime.datetime.now()-datetime.timedelta(days=1))
    if event_end_time:
        event_end_time=datetime.datetime.strptime(event_end_time, "%Y-%m-%d %H:%M:%S")
        clauses.append(syslog.created <= event_end_time)
    else:
        clauses.append(syslog.created <= datetime.datetime.now())
    if action and action!='All':
        clauses.append(syslog.action == action)
    if section and section!='All':
        clauses.append(syslog.section == section)
    if ip and ip !="":
        clauses.append(syslog.ip.contains(ip))
    if userid:
        user=db.get_user(userid)
        if not user:
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        else:
            clauses.append(syslog.user_id == user.id)
    expr=""
    users=db.User
    events=[]
    selector=[syslog.created,syslog.action,syslog.section,syslog.ip,syslog.agent,syslog.data,syslog.id,users.username,users.first_name,users.last_name]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=syslog.select(*selector).join(users).where(expr)
        else:
            query=syslog.select(*selector).join(users)
        query=query.order_by(syslog.id.desc())
        events=list(query.dicts())
    except Exception as e:
        log.error(e)
        return buildResponse({"status":"failed", "err":str(e)}, 200)
    return buildResponse(events, 200)



@app.route('/api/devlogs/details/list', methods = ['POST'])
@login_required(role='admin', perm={'device':'read'})
def dev_events_details_list():
    """return list of event details(types) for filters"""
    input = request.json
    devid=input.get('devid', False)
    event=db_events.select(event.details)
    if devid:
        dev=db_device.get_device(devid)
        if not dev:
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        else:
            event=event.where(event.devid == dev.id)
    event=event.group_by(event.details).order_by(event.id.desc())
    res=list(event.dicts())
    return buildResponse(res, 200)

@app.route('/api/dashboard/stats', methods = ['POST'])
@login_required(role='admin', perm={'device':'read'})
def dashboard_stats():
    """return dashboard data"""
    input = request.json
    versioncheck = input.get('versioncheck',False)
    VERSIONFILE="_version.py"
    from _version import __version__
    res={}
    res['version']=__version__
    # get past 24h failed logins and success logins from auth
    auth=db_AA.Auth
    res['FailedLogins']=auth.select().where(auth.ltype=='failed',auth.created>(datetime.datetime.now()-datetime.timedelta(days=1))).count()
    res['SuccessfulLogins']=auth.select().where(auth.ltype=='loggedin', auth.created>(datetime.datetime.now()-datetime.timedelta(days=1))).count()
    # get past 24h Critical and WARNING and info from events and also Total events
    event=db_events.Events
    res['Critical']=event.select().where(event.level=='Critical', event.eventtime>(datetime.datetime.now()-datetime.timedelta(days=1))).count()
    res['Warning']=event.select().where(event.level=='Warning', event.eventtime>(datetime.datetime.now()-datetime.timedelta(days=1))).count()
    res['Info']=event.select().where(event.level=='info', event.eventtime>(datetime.datetime.now()-datetime.timedelta(days=1))).count()
    res['Events']=event.select().count()
    interfaces = util.get_ethernet_wifi_interfaces()
    hwid = util.generate_serial_number(interfaces)
    install_date=False
    try:
        install_date=db_sysconfig.get_sysconfig('install_date')
    except:
        pass
    if not install_date or install_date=='':
        install_date=datetime.datetime.now()
        db_sysconfig.set_sysconfig('install_date',install_date.strftime("%Y-%m-%d %H:%M:%S"))
        install_date=install_date.strftime("%Y-%m-%d %H:%M:%S")
    if install_date:
        res['serial']=hwid+"-"+datetime.datetime.strptime(install_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
    else:
        res['serial']=False
    # get total users , Total devices , total auth , total acc
    acc=db_AA.Account
    devs=db_device.Devices
    res['Users']=db.User.select().count() - 1
    res['Devices']=devs.select().count()
    res['Auth']=auth.select().count()
    res['Acc']=acc.select().count()
    res['Registred']=False
    res['license']=False
    username=False
    internet_connection=True
    # check for internet connection before getting data from website
    feedurl="https://mikrowizard.com/tag/Blog/feed/?orderby=latest"
    test_url="https://google.com"
    try:
        req = requests.get(test_url, timeout=(0.5,1)) 
        req.raise_for_status()
    except Exception as e:
        log.error(e)
        internet_connection=False
        pass
    try:
        username = db_sysconfig.get_sysconfig('username')
        params={
            "serial_number": res['serial'],
            "username": username.strip(),
            "version": __version__
        }
        if versioncheck:
            params['versioncheck'] = True 
        url="https://mikrowizard.com/wp-json/mikrowizard/v1/get_update"
        # send post request to server mikrowizard.com with params in json
        try:
            if internet_connection:
                response = requests.post(url, json=params)
                response=response.json()
                res['license']=response.get('license',False)
        except:
            pass
    except:
        pass
    if username:
        res['username']=username
    res['blog']=[]
    noconnectiondata={
                "content": "Unable to connect to mikrowizard.com! please check server connection",
                "media_content": "data:image/png;base64,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",
                "summery": "Unable to connect mikrowizard.com to get latest News! <a  target=\"_blank\" href=\"https://mikrowizard.com/plan-your-project-with-your-software/\">Read More</a>",
                "title": "Connection Error"
            }
    try:
        if internet_connection:
            feed = feedparser.parse(feedurl)['entries']
        else:
            feed = []
        if len(feed) >0:
            for f in feed:
                tmp={}
                tmp['title']=f['title']
                tmp['content']=f['content'][0]['value']
                tmp['summery']=f['summary'][0:100]+" ... " + '<a  target="_blank" href="'+f['link']+'">Read More</a>'
                tmp['media_content']=f['media_content'][0]['url']
                res['blog'].append(tmp)
        else:
            res['blog'].append(noconnectiondata)
    except:
        res['blog'].append(noconnectiondata)
        pass

    return buildResponse(res, 200)

@app.route('/api/get_version', methods = ['POST','GET'])
def get_version():
    """return version info and serial in crypted format for front updater service"""
    VERSIONFILE="_version.py"
    from _version import __version__
    res={}
    res['version']=__version__
    try:
        res['username']=username = db_sysconfig.get_sysconfig('username')
    except:
        res['username']=False
    interfaces = util.get_ethernet_wifi_interfaces()
    hwid = util.generate_serial_number(interfaces)
    install_date=False
    try:
        install_date=db_sysconfig.get_sysconfig('install_date')
    except:
        pass
    if install_date:
        res['serial']=hwid + "-" + datetime.datetime.strptime(install_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
    else:
        res['serial']=False
    res=util.crypt_data(json.dumps(res))
    return buildResponse(res, 200)

@app.route('/api/dashboard/traffic', methods = ['POST'])
@login_required(role='admin', perm={'device':'read'})
def dashboard_traffic():
    """return all devices traffic information"""
    input = request.json
    devid='all'
    chart_type=input.get('type','bps')
    delta=input.get('delta',"live")
    interface=input.get('interface','total')
    if delta not in ["5m","1h","daily","live"]:
        return buildResponse({'status': 'failed'},200,error="Wrong Data")
    
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
    try:
        res={
            'id':devid,
            'sensors':['rx-total','tx-total']
        }
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
        data_keys=['tx-{}'.format(interface),'rx-{}'.format(interface)]
        if chart_type=='bps':
            data_keys=['tx-{}'.format(interface),'rx-{}'.format(interface)]
        elif chart_type=='pps':
            data_keys=['txp-{}'.format(interface),'rxp-{}'.format(interface)]
        for idx, val in enumerate(data_keys):
            for d in data[val]:
                if len(lables) <= len(data[val]):
                    lables.append(datetime.datetime.fromtimestamp(d[0]/1000))
                temp.append(round(d[1],1))
            datasets.append({'label':val,'borderColor': colors[idx],'type': 'line','yAxisID': ids[idx],'data':temp,'unit':val.split("-")[0],'backgroundColor': colors[idx],'pointHoverBackgroundColor': '#fff'})
            temp=[]
        res["data"]={'labels':lables,'datasets':datasets}
        
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed'}, 200, error=e)
        pass
    return buildResponse(res,200)