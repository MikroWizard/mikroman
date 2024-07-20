#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_sysconfig.py: API for MikroWizard system config
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request

from libs.db import db_sysconfig,db_syslog
from libs import util
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import time
import logging
import json

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
    for k,v in input.items():
        if k=="default_password" and v['value']=="":
            continue
        elif k=="default_user" and v['value']=="":
            continue
        elif k=="default_password" or k=="default_user":
            v['value']=util.crypt_data(v['value'])
        data.append({"key":k,"value":v['value'],"modified":"NOW"})
    db_syslog.add_syslog_event(get_myself(), "Sys Config","Update", get_ip(),get_agent(),json.dumps(input))
    db_sysconfig.save_all(data)
    
    return buildResponse({"status":"success"})
