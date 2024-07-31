#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_bakcups.py: API for managing bakcups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request, jsonify,session

from libs.db import db_tasks,db_backups,db_device,db_syslog,db_user_group_perm
from libs import util
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import bgtasks
import logging
import json
import datetime
from functools import reduce
import operator
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
log = logging.getLogger("api.firmware")

@app.route('/api/backup/make', methods = ['POST'])
@login_required(role='admin',perm={'backup':'write'})
def backup_create():
    input = request.json
    devids=input.get('devids',False)
    status=db_tasks.backup_job_status().status
    if not status:
        db_syslog.add_syslog_event(get_myself(), "Backup Managment","Create", get_ip(),get_agent(),json.dumps(input))
        if devids=="0":
            all_devices=list(db_device.get_all_device())
            bgtasks.backup_devices(devices=all_devices)
        else:
            devices=db_device.get_devices_by_id(devids)
            bgtasks.backup_devices(devices=devices)
        return buildResponse([{'status': status}],200)
    else:
        return buildResponse([{'status': status}],200)


@app.route('/api/backup/list', methods = ['POST'])
@login_required(role='admin',perm={'backup':'read'})
def backup_list():
    input = request.json
    event_start_time=input.get('start_time',False)
    event_end_time=input.get('end_time',False)
    devid = input.get('devid',False)
    search = input.get('search')
    uid = session.get("userid") or False
    if not devid:
        devs=list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
        dev_ids=[dev.id for dev in devs]
    else:
        dev=db_device.get_device(devid)
        if not dev:
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        dev_ids=[devid]
    backups = db_backups.Backups
    log.error("1")
    clauses = []
    clauses.append(backups.devid << dev_ids)
    if event_start_time:
        event_start_time=event_start_time.split(".000Z")[0]
        event_start_time=datetime.datetime.strptime(event_start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(backups.created >= event_start_time)
    else:
        clauses.append(backups.created >= datetime.datetime.now()-datetime.timedelta(days=1))
    if event_end_time:
        event_end_time=event_end_time.split(".000Z")[0]
        event_end_time=datetime.datetime.strptime(event_end_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(backups.created <= event_end_time)
    else:
        clauses.append(backups.created <= datetime.datetime.now())
    expr=""
    devs=db_device.Devices
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=backups.select().where(expr)
        else:
            query=backups.select()
        query=query.order_by(backups.id.desc())
        backups=list(query)
    except Exception as e:
        log.error(e)
        return buildResponse({"status":"failed", "err":str(e)}, 200)
    reply=[]
    log.error("backups")
    if search and ISPRO:
        backups=utilpro.search_in_backups(search, backups)
    for back in backups:
        data={}
        if back.devid:
            dev=back.devid
            data['id']=back.id
            data['filesize']=util.sizeof_fmt(back.filesize)
            data['created']=back.created
            data['devname']=dev.name
            data['devip']=dev.ip
            data['devmac']=dev.mac
        else:
            data['id']=back.id
            data['filesize']=util.sizeof_fmt(back.filesize)
            data['created']=back.created
            data['devname']='Deleted  Device'
            data['devip']='' 
            data['devmac']=''
        reply.append(data)
    return buildResponse(reply, 200)

@app.route('/api/backup/get', methods = ['POST'])
@login_required(role='admin',perm={'backup':'read'})
def backup_get():
    input = request.json
    id=input.get('id')
    try:
        back=db_backups.get_backup(id)
        path=back.dir
        with open(path, 'r') as file:
            file_content = file.read()
    except Exception as e:
        log.error(e)
        return buildResponse({"status":"failed"}, 200)
    return buildResponse({"content":file_content}, 200)

@app.route('/api/backup/status', methods = ['POST'])
@login_required(role='admin',perm={'backup':'read'})
def backup_status():
    status=db_tasks.update_check_status().status
    return jsonify({'status': status})
