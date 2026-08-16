#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_sysconfig.py: API for MikroWizard system config
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request
import uwsgi
import signal
import os
from libs.db import db_sysconfig,db_syslog, db_tasks
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
    """get all tasks"""
    input = request.json
    task_signal = int(input['signal'])
    task=db_tasks.get_task_by_signal(task_signal)
    res=[]
    #remove spooler file to stop task
    #list files under directory
    if not task:
        return buildResponse({'result':'failed','err':"No task"}, 200)
    spooldir=uwsgi.opt['spooler'].decode()+'/'+str(task_signal)
    #list all files and remove them in spooldir
    files = []
    try:
        if os.path.exists(spooldir):
            for file in os.listdir(spooldir):
                file_path = os.path.join(spooldir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    files.append(file)
    except Exception as e:
        log.error(f"Error removing spool files: {str(e)}")
        return buildResponse({'result':'failed','err':str(e)}, 200)
    pid=uwsgi.spooler_pid()
    #kill pid to stop task
    if task_signal not in [130,140]:
        try:
            os.kill(pid, signal.SIGTERM)  # Attempt graceful shutdown
        except ProcessLookupError:
            return buildResponse({'result':'failed','err':'Spooler not running'}, 200)
        except PermissionError:
            return buildResponse({'result':'failed','err':'Permission denied to reload spooler process'}, 200)
        except Exception as e:
            return buildResponse({'result':'failed','err':str(e)}, 200)
    else:
        task.action="cancel"
        task.status=False
        task.save()
        return buildResponse({"status":"success"})
    task.status=False
    task.action="None"
    task.save()
    return buildResponse({"status":"success"})

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

