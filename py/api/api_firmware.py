#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_firmware.py: API for managing firmware
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request, jsonify,session,send_file
from playhouse.shortcuts import model_to_dict
import datetime
from libs.db import db_tasks,db_sysconfig,db_device,db_firmware,db_syslog
from libs import util
from libs.webutil import app, login_required, get_myself,buildResponse,get_myself,get_ip,get_agent
import bgtasks
import re
import logging
log = logging.getLogger("api.firmware")
import json

@app.route('/api/firmware/check_firmware_update', methods = ['POST'])
@login_required(role='admin',perm={'device':'write'})
def check_firmware_update():
    """Chck fimware update status"""
    input = request.json
    devids=input.get('devids',"0")
    status=db_tasks.update_check_status().status
    uid = session.get("userid") or False
    if not uid:
        return buildResponse({'result':'failed','err':"No User"}, 200)
    #if devices is [0] then check firmware for all devices of user
    if not status:
        bgtasks.check_devices_for_update(devices=devids,uid=uid)
        db_syslog.add_syslog_event(get_myself(), "Firmware","Check", get_ip(),get_agent(),json.dumps(input))
        res={'status': True}
    else:
        res={'status': status}

    return buildResponse(res,200)

@app.route('/api/firmware/check_task_status', methods = ['GET'])
@login_required(role='admin',perm={'device':'read'})
def check_task_status():
    """Return firmware update check service status"""
    status=db_tasks.update_check_status().status
    return jsonify({'status': status})

@app.route('/api/firmware/update_firmware', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def update_device():
    """Update devices"""
    status=db_tasks.update_job_status().status
    input=request.json
    devids=input.get('devids',"0")
    uid = session.get("userid") or False
    if not uid:
        return buildResponse({'result':'failed','err':"No User"}, 200)
    if not status:
        db_syslog.add_syslog_event(get_myself(), "Firmware","update", get_ip(),get_agent(),json.dumps(input))
        bgtasks.update_device(devices=devids,uid=uid)
        res={'status': True}
    else:
        res={'status': status}
    return buildResponse(res,200)

@app.route('/api/firmware/get_firms', methods = ['POST'])
@login_required(role='admin',perm={'settings':'full'})
def get_firms():
    """get list of of downloaded firmwares in local repo"""
    input = request.json or {}
    page = input.get('page')
    size = input.get('size')
    search = input.get('search')

    reply = db_firmware.query_firms(page, size, search).dicts()
    data={
        "firms":reply,
        "updateBehavior":db_sysconfig.get_sysconfig("old_firmware_action"),
        "firmwaretoinstall":db_sysconfig.get_sysconfig("latest_version"),
        "firmwaretoinstallv6":db_sysconfig.get_sysconfig("old_version"),
    }
    return buildResponse(data, 200)

@app.route('/api/firmware/get_downloadable_firms', methods = ['POST'])
@login_required(role='admin',perm={'settings':'full'})
def get_downloadable_firms():
    """get list of availble Firmwares from Mikrotik Official webstire"""
    input = request.json or {}
    versions=util.get_mikrotik_versions()
    versions = sorted(versions, key=lambda x: [int(y) if y.isdigit() else int(re.sub(r'\D', '', y)) for y in x.split('.')])

    return buildResponse({"versions":versions}, 200)

@app.route('/api/firmware/download_firmware_to_repository', methods = ['POST'])
@login_required(role='admin',perm={'settings':'full'})
def download_firmware_to_repository():
    """Download Firmware from Mikrotik Official website"""
    input = request.json or {}
    version=input.get('version')
    status=db_tasks.downloader_job_status().status
    
    if not status:
        db_syslog.add_syslog_event(get_myself(), "Firmware","Download", get_ip(),get_agent(),json.dumps(input))
        bgtasks.download_firmware(version=version)
        return buildResponse({'status': True}, 200)
    else:
        return buildResponse({'status': status}, 200)

@app.route('/api/firmware/update_firmware_settings', methods = ['POST'])
@login_required(role='admin',perm={'settings':'write'})
def update_firmware_settings():
    """Change system settings for firmware update"""
    input = request.json or {}
    updateBehavior=input.get('updatebehavior')
    firmwaretoinstall=input.get('firmwaretoinstall')
    firmwaretoinstallv6=input.get('firmwaretoinstallv6')
    db_sysconfig.update_sysconfig("old_firmware_action", updateBehavior)
    db_sysconfig.update_sysconfig("latest_version", firmwaretoinstall)
    db_sysconfig.update_sysconfig("old_version", firmwaretoinstallv6)
    db_syslog.add_syslog_event(get_myself(), "Firmware","settings", get_ip(),get_agent(),json.dumps(input))
    return buildResponse({'status': True}, 200)

def serialize_datetime(obj): 
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 

@app.route('/api/firmware/get_firmware/<firmid>', methods = ['POST','GET'])
def get_firmware(firmid):
    """Download firmware of given id from repo"""
    firm=db_firmware.get_firm(firmid)
    dev_ip=request.remote_addr
    # log.error(dev_ip)
    # if dev_ip:
    #     dev=db_device.query_device_by_ip(dev_ip)
    # if not dev:
    #     return buildResponse({'result':'failed', 'err':"Device not found"}, 200)

    if firm:
        data={
            "devip":dev_ip,
            # "devid":dev.id,
            "firm":model_to_dict(firm),
            }
        db_syslog.add_syslog_event(get_myself(), "Firmware","download", get_ip(),get_agent(),json.dumps(data,default=serialize_datetime))
        # if dev.arch != firm.architecture:
        #     return buildResponse({'result':'failed','err':"Wrong architecture"}, 200)
        path=firm.location
        return send_file(path, as_attachment=True)
    # log.error(dev)
    return buildResponse({'result':'failed','err':"somthing went wrong"}, 200)

