#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_user_tasks.py: API for create modify schedule tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request
from libs.db import db_syslog,db_user_tasks
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
from functools import reduce
import operator
from crontab import CronTab,CronSlices
import logging
from cron_descriptor import get_description
import json
from pathlib import Path
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
log = logging.getLogger("api.usertasks")


@app.route('/api/user_tasks/list', methods = ['POST'])
@login_required(role='admin',perm={'task':'read'})
def user_tasks_list():
    """return user task list"""
    input = request.json
    name=input.get('name',False)
    description=input.get('description',False)
    action=input.get('action',False)
    task_type=input.get('task_type',False)
    utaks=db_user_tasks.UserTasks
    # build where query
    clauses = []
    if name:
        clauses.append(utaks.name.contains(name))
    if description:
        clauses.append(utaks.description.contains(description))
    if action:
        clauses.append(utaks.action == action)
    if task_type:
        clauses.append(utaks.task_type == task_type)
    if not ISPRO:
        clauses.append(utaks.task_type != 'firmware')
    clauses.append(utaks.task_type != 'vault')
    clauses.append(utaks.task_type != 'snipet_exec')
    expr=""
    logs = []
    selector=[utaks.id,utaks.name,utaks.description,utaks.desc_cron,utaks.action,utaks.task_type,utaks.dev_ids,utaks.snippetid,utaks.data,utaks.cron,utaks.selection_type,utaks.created]
    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query=utaks.select(*selector).where(expr)
        else:
            query=utaks.select(*selector)
        query=query.order_by(utaks.id.desc())
        logs=list(query.dicts())
    except Exception as e:
        return buildResponse({"status":"failed", "err":str(e)},200)
    return buildResponse(logs,200)

@app.route('/api/user_tasks/create', methods = ['POST'])
@login_required(role='admin',perm={'task':'write'})
def user_tasks_create():
    """crate user task"""
    input = request.json
    name=input.get('name',False)
    description=input.get('description',False)
    snippetid=input.get('snippetid',False)
    members=input.get('members', False)
    cron=input.get('cron',False)
    action=input.get('action',False)
    task_type=input.get('task_type',"backup")
    selection_type=input.get('selection_type',False)
    taskdata=input.get('data',False)
    utasks=db_user_tasks.UserTasks
    
    # todo
    # add owner check devids and dev groups with owner
    if not name or not description:
        return buildResponse({'status': 'failed'},200,error="Wrong name/desc")
    #check if cron is valid and correct
    if cron and not CronSlices.is_valid(cron):
        return buildResponse({'status': 'failed'},200,error="Wrong Cron")
    
    data={
        'name':name,
        'description':description,
        'snippetid':int(snippetid) if snippetid else None,
        'cron':cron,
        'desc_cron': get_description(cron),
        'action': action,
        'task_type':task_type,
        'selection_type':selection_type,
        'data':json.dumps(taskdata) if taskdata else None
    }

    if selection_type not in ["devices","groups"]:
        return buildResponse({'status': 'failed'}, 200, error="Wrong member type")
    
    if task_type not in ["backup","snippet","firmware"]:
        return buildResponse({'status': 'failed'}, 200, error="Wrong task type")
    try:
        task=utasks.create(**data)
        #add members to task
        if len(members):
            db_user_tasks.add_member_to_task(task.id, members, selection_type)
        taskid=task.id
        crontab = CronTab(user=True)
        directory=Path(app.root_path).parent.absolute()
        command = "python3 {}/task_run.py {}".format(directory,taskid)
        comment = "MikroWizard task #" + "taskid:{};".format(taskid)
        jobs = crontab.find_comment(comment)
        if len(list(jobs)) > 0:
            jobs = crontab.find_comment(comment)
            crontab.remove(jobs)
            crontab.write()
        job = crontab.new(command=command,comment=comment)
        job.setall(cron)
        crontab.write()
        db_syslog.add_syslog_event(get_myself(), "Task","Create", get_ip(),get_agent(),json.dumps(input))
        return buildResponse([{'status': 'success',"taskid":taskid}],200)
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed','massage':str(e)},200)    


@app.route('/api/user_tasks/edit', methods = ['POST'])
@login_required(role='admin',perm={'task':'write'})
def user_tasks_edit():
    """create edit user task"""
    input = request.json
    name=input.get('name',False)
    task_id=input.get('id', False)
    description=input.get('description',False)
    snippetid=input.get('snippetid',False)
    members=input.get('members', False)
    cron=input.get('cron',False)
    action=input.get('action',False)
    task_type=input.get('task_type',"backup")
    selection_type=input.get('selection_type',False)
    taskdata=input.get('data', False)
    # todo
    # add owner check devids and dev groups with owner
    if not name or not description:
        return buildResponse({'status': 'failed'},200,error="Wrong name/desc")
    # Check if cron is valid and correct
    if cron and not CronSlices.is_valid(cron):
        return buildResponse({'status': 'failed'},200,error="Wrong Cron")
        
    if selection_type not in ["devices","groups"]:
        return buildResponse({'status': 'failed'}, 200, error="Wrong member type")
    
    if task_type not in ["backup","snippet","firmware"]:
        return buildResponse({'status': 'failed'}, 200, error="Wrong task type")
    
    # check task exist and valid
    utask=db_user_tasks.get_object_or_none(db_user_tasks.UserTasks, id=task_id)
    
    data={
        'name':name,
        'description':description,
        'snippetid':int(snippetid) if snippetid else None,
        'cron':cron,
        'desc_cron': get_description(cron),
        'action': action,
        'task_type':task_type,
        'selection_type':selection_type,
        'data':json.dumps(taskdata) if taskdata else None
    }

    # Update utask
    utasks=db_user_tasks.UserTasks
    utasks.update(**data).where(utasks.id == utask.id).execute()
    
    # Delete old members
    db_user_tasks.delete_members(utask.id)
    # Add new members
    if len(members):
        db_user_tasks.add_member_to_task(task_id, members, selection_type)
    
    try:
        taskid=utask.id
        crontab = CronTab(user=True)
        directory=Path(app.root_path).parent.absolute()
        command = "/usr/local/bin/python3 {}/task_run.py {}  >> /var/log/cron.log 2>&1".format(directory,taskid)
        comment = "MikroWizard task #" + "taskid:{};".format(taskid)
        jobs = crontab.find_comment(comment)
        if len(list(jobs)) > 0:
            jobs = crontab.find_comment(comment)
            crontab.remove(jobs)
            crontab.write()
        job = crontab.new(command=command,comment=comment)
        job.setall(cron)
        crontab.write()
        db_syslog.add_syslog_event(get_myself(), "Task","Edit", get_ip(),get_agent(),json.dumps(input))
        return buildResponse([{'status': 'success',"taskid":taskid}],200)
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed','massage':str(e)},200)   


@app.route('/api/user_tasks/delete', methods = ['POST'])
@login_required(role='admin',perm={'task':'full'})
def user_tasks_delete():
    """delete user task"""
    input = request.json
    taskid=input.get('taskid',False)
    utaks=db_user_tasks.UserTasks
    crontab = CronTab(user=True)
    utask=db_user_tasks.get_object_or_none(db_user_tasks.UserTasks, id=taskid)
    comment = "MikroWizard task #" + "taskid:{};".format(taskid)
    if not taskid:
        return buildResponse({'status': 'failed'},200,error="Wrong name/desc")
    try:
        jobs = crontab.find_comment(comment)
        if len(list(jobs)) > 0:
            jobs = crontab.find_comment(comment)
            crontab.remove(jobs)
            crontab.write()
        # Delete old members
        db_user_tasks.delete_members(utask.id)
        # delete task 
        res=utaks.delete().where(utaks.id == utask.id).execute()
        if res:
            db_syslog.add_syslog_event(get_myself(), "Task","Delete", get_ip(),get_agent(),json.dumps(input))
            return buildResponse([{'status': 'success',"taskid":res}],200)
        else:
            return buildResponse([{'status': 'failed',"massage":"record not exist"}],200)
    except Exception as e:
        log.error(e)
        return buildResponse({'status': 'failed','massage':str(e)},200)    




