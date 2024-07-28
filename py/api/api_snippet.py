#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_snippet.py: API for code snippets
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request,session

from libs.db import db_user_tasks,db_syslog,db_tasks,db_sysconfig
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
from functools import reduce
import bgtasks
import operator
import logging
import json
import datetime
log = logging.getLogger("api.snippet")

@app.route('/api/snippet/list', methods = ['POST'])
@login_required(role='admin',perm={'snippet':'read'})
def user_snippet_list():
    """return snippets list """
    input = request.json
    name=input.get('name',False)
    description=input.get('description',False)
    content=input.get('content',False)
    snips=db_user_tasks.Snippets
    page=input.get('page',0)
    size=input.get('size',10000)
    # build where query
    clauses = []
    if name and name!="":
        clauses.append(snips.name.contains(name))
    if description and description!="":
        clauses.append(snips.description.contains(description))
    if content and content!="":
        clauses.append(snips.content == content)

    expr=""
    logs = []
    selector=[snips.id,snips.name,snips.description,snips.content,snips.created]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=snips.select(*selector).where(expr)
        else:
            query=snips.select(*selector)
        query=query.order_by(snips.id.desc())
        query=query.paginate(page,size)
        logs=list(query.dicts())
    except Exception as e:
        return buildResponse({"status":"failed", "err":str(e)},400)
    return buildResponse(logs,200)

@app.route('/api/snippet/save', methods = ['POST'])
@login_required(role='admin',perm={'snippet':'write'})
def user_snippet_save():
    """save or create snippets"""

    input = request.json
    id=input.get('id', 0)
    name=input.get('name', False)
    description=input.get('description', False)
    content=input.get('content', False)

    # if id is 0 then we are creating new snippet
    # else edit the snippet with provided id
    if id==0:
        snippet=db_user_tasks.get_snippet_by_name(name)
        if snippet:
            return buildResponse({"result":"failed","err":"Snippet already exists"}, 200)
        snippet=db_user_tasks.create_snippet(name,description,content)
        if snippet:
            db_syslog.add_syslog_event(get_myself(), "Snippet","Create", get_ip(),get_agent(),json.dumps(input))
            return buildResponse({"result":"success"}, 200)
        else:
            return buildResponse({"result":"failed","err":"Snippet create failed"}, 200)
    else:
        snippet=db_user_tasks.get_snippet(id)
        if snippet:
            db_syslog.add_syslog_event(get_myself(), "Snippet","Update", get_ip(),get_agent(),json.dumps(input))
            snippet=db_user_tasks.update_snippet(id, name, description, content)
            return buildResponse({"result":"success"}, 200)
        else:
            return buildResponse({"result":"failed","err":"Snippet not found"}, 200)
        
@app.route('/api/snippet/delete', methods = ['POST'])
@login_required(role='admin',perm={'snippet':'full'})
def user_snippet_delete():
    input = request.json
    id=input.get('id', 0)
    snippet=db_user_tasks.get_snippet(id)
    if snippet:
        db_syslog.add_syslog_event(get_myself(), "Snippet","Delete", get_ip(),get_agent(),json.dumps(input))
        snippet=db_user_tasks.delete_snippet(id)
        return buildResponse({"result":"success"}, 200)
    else:
        return buildResponse({"result":"failed","err":"Failed to delete snippet"}, 200)
    
@app.route('/api/snippet/exec', methods = ['POST'])
@login_required(role='admin',perm={'task':'write'})
def exec_snippet():
    """crate user task"""
    input = request.json
    description=input.get('description',None)
    snippetid=input.get('id',False)
    members=input.get('members', False)
    task_type=input.get('task_type',"backup")
    selection_type=input.get('selection_type',False)
    # taskdata=input.get('data',False)
    utasks=db_user_tasks.UserTasks
    
    # todo
    # add owner check devids and dev groups with owner
    if not description:
        return buildResponse({'status': 'failed'},200,error="Wrong name/desc")
    #check if cron is valid and correct
    taskdata={}
    taskdata['memebrs']=members
    taskdata['owner']=members
    snipet=db_user_tasks.get_snippet(snippetid)
    if snipet:
        taskdata['snippet']={'id':snipet.id,'code':snipet.content,'description':snipet.description,'name':snipet.name}
    else:
        return buildResponse({'status': 'failed'}, 200, error="Wrong snippet")

    if selection_type not in ["devices","groups"]:
        return buildResponse({'status': 'failed'}, 200, error="Wrong member type")
    if task_type != 'snipet_exec':
        return buildResponse({'status': 'failed'}, 200, error="Wrong task type")
    try:
        data={
            'name':snipet.name,
            'description':description,
            'snippetid':int(snippetid),
            'cron':None,
            'desc_cron': None,
            'action': 'snipet_exec',
            'task_type':'snipet_exec',
            'selection_type':selection_type,
            'data':json.dumps(taskdata),
            'created': datetime.datetime.now()
        }
        task=utasks.create(**data)
        status=db_tasks.exec_snipet_status().status
        uid = session.get("userid") or False
        default_ip=db_sysconfig.get_sysconfig('default_ip')
        if not uid:
            return buildResponse({'result':'failed','err':"No User"}, 200)
        if not status:
            bgtasks.exec_snipet(task=task,default_ip=default_ip,devices=members,uid=uid)
            res={'status': True}
        else:
            res={'status': status}
        #add members to task
        db_syslog.add_syslog_event(get_myself(), "Snippet","execute", get_ip(),get_agent(),json.dumps(input))
        return buildResponse([{'status': 'success'}],200)
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed','massage':str(e)},200)    

    
@app.route('/api/snippet/executed', methods = ['POST'])
@login_required(role='admin',perm={'task':'write'})
def get_executed_snippet():
    """crate user task"""
    input = request.json
    id=input.get('id', False)
    snipet=db_user_tasks.get_snippet(id)
    if not snipet:
        return buildResponse({'status': 'failed'}, 200, error="Wrong snippet")
    utasks=db_user_tasks.UserTasks
    tasks=utasks.select().where(utasks.snippetid==id).where(utasks.task_type=='snipet_exec')
    taks_ids=[task.id for task in tasks]
    task_res=db_tasks.TaskResults
    executed_tasks=task_res.select().where(task_res.external_id<<taks_ids).order_by(task_res.id.desc())
    executed_tasks=list(executed_tasks.dicts())
    for task in executed_tasks:
        task['result']=json.loads(task['result'])
        task['info']=json.loads(task['info'])
    if executed_tasks:
        return buildResponse(executed_tasks, 200)
    else:
        return buildResponse({'status': 'failed'}, 200)
