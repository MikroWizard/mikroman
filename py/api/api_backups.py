#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_bakcups.py: API for managing bakcups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request, jsonify

from libs.db import db_tasks,db_backups,db_device,db_syslog
from libs import util
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import bgtasks
import logging
import json

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
    page = input.get('page')
    devid = input.get('devid',False)
    size = input.get('size')
    search = input.get('search')
    backups = db_backups.query_backup_jobs(page, size, search,devid=devid)
    reply=[]
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
    back=db_backups.get_backup(id)
    path=back.dir
    with open(path, 'r') as file:
        file_content = file.read()
    return buildResponse({"content":file_content}, 200)

@app.route('/api/backup/status', methods = ['POST'])
@login_required(role='admin',perm={'backup':'read'})
def backup_status():
    status=db_tasks.update_check_status().status
    return jsonify({'status': status})
