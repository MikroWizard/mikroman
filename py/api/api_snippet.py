#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_snippet.py: API for code snippets
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request

from libs.db import db_user_tasks,db_syslog
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
from functools import reduce
import operator
import logging
import json

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