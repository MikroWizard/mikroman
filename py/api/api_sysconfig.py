#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_sysconfig.py: API for MikroWizard system config
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request
try:
    import uwsgi
except ImportError:
    uwsgi = None
import signal
import os
from libs.db import db_sysconfig,db_syslog, db_tasks
from libs import task_tracker
from libs import util
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import time
import logging
import json
from pathlib import Path

log = logging.getLogger("api.sysconfig")

@app.route('/api/sysconfig/get_all', methods = ['POST'])
@login_required(role='admin',perm={'settings':'read'})
def sysconfig_get_all():
    """get all system configs"""

    input = request.json
    sysconfig=db_sysconfig.get_all()
    res={}
    for s in sysconfig:
        res[s.key]={"value":s.value,"modified":s.modified}
    return buildResponse({"sysconfigs":res})


@app.route('/api/sysconfig/save_all', methods = ['POST'])
@login_required(role='admin',perm={'settings':'write'})
def sysconfig_save_all():
    """save system configs"""

    input = request.json
    data=[]
    now=time.time()
    for k, v in input.items():
        if k in ["default_password", "default_user", "smtp_password", "ai_api_key"]:
            if v.get('value') == "":
                # If empty on submit, preserve existing encrypted value from database
                existing = db_sysconfig.get_sysconfig(k)
                v['value'] = existing if existing else ""
            elif v.get('value') == "__CLEAR__":
                v['value'] = ""
            else:
                v['value'] = util.crypt_data(v['value'])
        elif k == "update_mode":
            v['value'] = json.dumps(v['value'])
        elif k == "ai_openrouter_models":
            # Ensure it is stored as a JSON string (frontend sends it as array)
            if isinstance(v['value'], list):
                v['value'] = json.dumps([m for m in v['value'] if m])
            elif not isinstance(v['value'], str):
                v['value'] = '[]'
        elif k == "speedtest_servers":
            if isinstance(v['value'], list):
                v['value'] = json.dumps(v['value'])
            elif not isinstance(v['value'], str):
                v['value'] = '[]'
        elif k == "ai_model":
            if isinstance(v.get('value'), str):
                v['value'] = v['value'].strip()
        data.append({"key":k,"value":v['value'],"modified":"NOW"})
    db_syslog.add_syslog_event(get_myself(), "Sys Config","Update", get_ip(),get_agent(),json.dumps(input))
    db_sysconfig.save_all(data)
    
    return buildResponse({"status":"success"})


@app.route('/api/tasks/list', methods = ['POST'])
@login_required(role='admin',perm={'settings':'read'})
def tasks_list():
    """get all tasks"""
    input = request.json
    res=[]
    res=db_tasks.get_all().dicts()
    for t in res:
        t['name']=t['name'].replace("-"," ").replace("_"," ")
    return buildResponse({"tasks":res})

@app.route('/api/tasks/stop', methods = ['POST'])
@login_required(role='admin',perm={'settings':'write'})
def stop_task():
    """Stop/cancel a background task.

    Removes its queued spool files and asks the running instance to stop gracefully
    (devices in progress finish, remaining devices are skipped). Pressing Stop again after
    2 minutes, or sending force=true, kills the exact spooler PID running it - except for
    firmware update, firmware download, scan and vault, which are never killed.
    """
    input = request.json or {}
    try:
        task_signal = int(input['signal'])
    except (KeyError, TypeError, ValueError):
        return buildResponse({'result': 'failed', 'err': 'Invalid signal'}, 200)
    task_id = input.get('task_id') or None
    force = str(input.get('force', '')).lower() in ('1', 'true', 'yes')
    try:
        res = task_tracker.stop_task(task_signal, task_id=task_id, force=force)
    except Exception as e:
        log.error(f"Error stopping task {task_signal}: {e}")
        return buildResponse({'result': 'failed', 'err': str(e)}, 200)
    log.info(f"Stop task {task_signal}: mode={res['mode']} removed={len(res['removed_files'])} killed={res['killed_pids']} cancelled_rows={res['cancelled_rows']}")
    if res['result'] != 'success':
        return buildResponse({'result': 'failed', 'err': 'No running or queued task'}, 200)
    return buildResponse({"status": "success", "mode": res['mode'], "killed": len(res['killed_pids']),
                          "removed": len(res['removed_files']), "cancelled": res['cancelled_rows']})

@app.route('/api/sysconfig/apply_update', methods = ['POST'])
@login_required(role='admin',perm={'settings':'write'})
def apply_update():
    """apply update"""
    input = request.json
    action = input['action']
    update_mode=db_sysconfig.get_sysconfig('update_mode')
    update_mode=json.loads(update_mode)

    if update_mode['mode']=='manual':
        if action=='update_mikroman':
            update_mode['update_back']=True
            db_sysconfig.set_sysconfig('update_mode',json.dumps(update_mode))
            Path('/app/reload').touch()
            return buildResponse({"status":"success"})
        if action=='update_mikrofront':
            update_mode['update_front']=True
            db_sysconfig.set_sysconfig('update_mode',json.dumps(update_mode))
            return buildResponse({"status":"success"})
    return buildResponse({"status":"success"})

