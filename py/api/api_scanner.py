#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_scanner.py: API for device scanner in network
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request

from libs.db import db_tasks,db_syslog
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import bgtasks
import json
import logging
log = logging.getLogger("api.scanner")

@app.route('/api/scanner/scan', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def scan_network():
    """Do scan requested network for given ip range to find mikrotik devices"""
    input = request.json
    start=input.get('start',False)
    end=input.get('end',False)
    port=input.get('port',8728)
    if not port:
        port=8728
    password=input.get('password',False)
    username=input.get('user',False)
    status=db_tasks.scanner_job_status().status

    if not status:
        if start and end and port:
            db_syslog.add_syslog_event(get_myself(), "Scanner","start", get_ip(),get_agent(),json.dumps(input))
            bgtasks.scan_with_ip(start=start,end=end,port=port,password=password,username=username,user=get_myself())
            return buildResponse({'status': True},200)
        else:
            return buildResponse({'status': status},200)
    else:
        return buildResponse({'status': status},200)

@app.route('/api/scanner/results', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def scan_resutls():
    """Do scan requested network for given ip range to find mikrotik devices"""
    input = request.json
    tasks=db_tasks.TaskResults
    #Get tasks that is task_type is ip-scan
    tasks=tasks.select().where(tasks.task_type=='ip-scan').order_by(tasks.id.desc())
    tasks=list(tasks.dicts())
    #Get task results
    return buildResponse({'status': True,'data':tasks},200)
