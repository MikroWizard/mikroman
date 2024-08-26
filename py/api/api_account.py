#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_account.py: API For managing accounts and permissions
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from ctypes import util
from flask import request, session, g, jsonify
from libs.util import ISPRO
from libs.db import db,db_permissions,db_user_group_perm,db_groups,db_sysconfig,db_syslog

import json
from libs import utilpro, webutil,account
from libs.webutil import app, login_required, get_myself , buildResponse
from libs.mschap3.mschap import nt_password_hash

import logging
log = logging.getLogger("api")

@app.route('/api/login', methods = ['POST'])
def login():
    """Logs the user in with username+password.
       On success returns the user object,
       on error returns error."""

    input = request.json or {}
    username = input.get('username')
    password = input.get('password')

    if not username or not password:
        return buildResponse({"status":"failed", "err":"Wrong user/pass"}, 200)

    u = db.get_user_by_username(username)
    if not u or not account.check_password(u.password, password) or u.role=='disabled':
        # error
        try:
            db_syslog.add_syslog_event(u.id, "User login","Failed login",webutil.get_ip(),webutil.get_agent(),json.dumps({"username":username,'reason':'wrong password'}))
        except:
            pass
        return buildResponse({"status":"failed", "err":"Wrong user/pass"}, 200)
    else:
        # success
        tz=db_sysconfig.get_sysconfig('timezone')
        # log.info("LOGIN OK agent={}".format(webutil.get_agent()))
        res={
            "username":u.username,
            "name":u.username,
            "partner_id":u.id,
            "uid":u.id,
            "first_name":u.first_name,
            "last_name":u.last_name,
            "role":u.role,
            "tags":u.tags,
            "tz":tz,
            "perms":json.loads(u.adminperms)
        }
        if ISPRO:
            prores=utilpro.do_login(res,input)
            if prores:
                return buildResponse(prores, 200)
        account.build_session(u, is_permanent=input.get('remember', True))
        db_syslog.add_syslog_event(u.id, "User login","Successful login",webutil.get_ip(),webutil.get_agent(),json.dumps({"username":username}))
        return buildResponse(res, 200)

@app.route('/api/user/create', methods = ['POST'])
@login_required(role='admin',perm={'users':'write'})
def create_user():
    """Create new user."""
    
    input = request.json or {}
    username  = input.get('username')
    passwd = input.get('password')
    email  = input.get('email')
    fname  = input.get('first_name')
    lname  = input.get('last_name')
    role   = input.get('role', 'user') 
    company  = input.get('company')
    adminperms = input.get('adminperms',[])
    userperms = input.get('userperms',[])

    if not username or not passwd or not fname or not lname or not role:
        resp={"status":"failed","err":"invalid data"}
        return buildResponse(resp, 200)

    u = db.get_user_by_username(username)
    if u:
        msg = "User Name already Taken: {}".format(username)
        resp={"status":"failed","err":msg}
        return buildResponse(resp, 200)

    err = account.check_password_validity(passwd)
    if err:
        err = "Invalid password : {}".format(err)
        resp={"status":"failed","err":err}
        return buildResponse(resp, 200)
    newpass = account.hash_password(passwd)
    nthashhex=''.join(list("{:02x}".format(ord(c)) for c in nt_password_hash(passwd)))
    # create new user
    u = db.User()
    u.username = username
    u.company = company
    u.first_name = fname
    u.last_name = lname
    u.password = newpass
    u.email= email
    u.adminperms= json.dumps(adminperms)
    u.hash = nthashhex
    u.tags = []
    u.role = role # set default to what makes sense to your app
    u.save(force_insert=True)
    account.new_signup_steps(u)
    for perm in userperms:
        db_user_group_perm.DevUserGroupPermRel.create_user_group_perm(u.id, int(perm['group_id']), int(perm['perm_id']))
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment","Create", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse(u, 200)

@app.route('/api/user/delete' ,methods=['POST'])
@login_required(role='admin', perm={'users':'full'})
def user_delete():
    """Deletes a user. Only for superusers"""
    input = request.json or {}
    uid = input.get('uid')
    try:
        u = db.get_user(uid)
    except:
        u=False
    if str(u.id) == "37cc36e0-afec-4545-9219-94655805868b" or str(u.username)=='system':
        resp={"status":"failed","err":"Cannot delete admin user"}
        return buildResponse(resp, 200)
    if not u:
        msg = "User not found: {}".format(uid)
        resp={"status":"failed","err":msg}
        return buildResponse(resp, 200)

    u.delete_instance(recursive=True)
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment", "Delete", webutil.get_ip(), webutil.get_agent(), json.dumps(input))
    return buildResponse({}, 200)

@app.route('/api/user/change_password' ,methods=['POST'])
@login_required
def user_change_password():
    """Changes user password."""
    input = request.json or {}
    uid = webutil.get_myself().id
    oldpass = input.get('oldpass')
    newpass = input.get('newpass')
    #check if oldpass is correct
    try:
        u = db.get_user(uid)
    except:
        u=False
        
    if not u or not account.check_password(u.password, oldpass):
        msg = "Current password is incorrect"
        resp={"status":"failed","err":msg}
        return buildResponse(resp, 200)
    
    err = account.check_password_validity(newpass)
    if not err:
        newpass = account.hash_password(newpass)
        nthashhex=''.join(list("{:02x}".format(ord(c)) for c in nt_password_hash(newpass)))
    else:
        err = "Invalid password : {}".format(err)
        resp={"status":"failed","err":err}
        return buildResponse(resp, 200)

    u.password = newpass
    
    u.hash = nthashhex
    u.save()
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment", "Change Password", webutil.get_ip(), webutil.get_agent(), json.dumps(input))
    resp={"status":"success"}
    return buildResponse(resp, 200)


@app.route('/api/logout', methods = ['POST'])
@login_required
def logout():
    """Logs out the user, clears the session."""
    db_syslog.add_syslog_event(webutil.get_myself(), "User Logout","User Logged out", webutil.get_ip(),webutil.get_agent(),json.dumps({'logout':True}))
    session.clear()
    return jsonify({}), 200


@app.route('/api/me', methods=['GET', 'POST'])
def me():
    """Return info about me."""
    me = get_myself()
    if me:
        res={
            "username":me.username,
            "first_name":me.first_name,
            "last_name":me.last_name,
            "role":me.role,
            "tags":me.tags,
            "uid":me.id,
            "perms":json.loads(me.adminperms),
            "tz":db_sysconfig.get_sysconfig('timezone'),
            "ISPRO":ISPRO
        }
        reply = res
    else:
        reply = {"username":"public","first_name":"guest","last_name":"guest","role":"admin"}
    return buildResponse(reply, 200)


@app.route('/api/user/edit', methods = ['POST'])
@login_required(role='admin',perm={'users':'write'})
def user_edit():
    """Edit user info. Only for admins with write perm"""
    err=False
    input = request.json or {}
    uid = input.get('id')
    username  = input.get('username')
    passwd = input.get('password')
    email  = input.get('email')
    fname  = input.get('first_name')
    lname  = input.get('last_name')
    role   = input.get('role', 'user') 
    adminperms = input.get('adminperms',[])

    if passwd:
        err = account.check_password_validity(passwd)
        if not err:
            newpass = account.hash_password(passwd)
            nthashhex=''.join(list("{:02x}".format(ord(c)) for c in nt_password_hash(passwd)))
        else:
            err = "Invalid password : {}".format(err)
            resp={"status":"failed","err":err}
            return buildResponse(resp, 200)
            
    try:
        u = db.get_user(uid)
    except:
        u=False
    
    if not u:
        msg = "User not found: {}".format(uid)
        resp={"status":"failed","err":msg}
        return buildResponse(resp, 200)
    ucheck = db.get_user_by_username(username)
    if ucheck and str(ucheck.id) != uid:
        msg = "User Name already Taken: {}".format(username)
        resp={"status":"failed","err":msg}
        return buildResponse(resp, 200)
    if username:
        u.username = username
    if fname:
        u.first_name = fname

    if lname:
        u.last_name = lname

    if role and str(u.id) != "37cc36e0-afec-4545-9219-94655805868b":
        u.role = role
    if adminperms and str(u.id) != "37cc36e0-afec-4545-9219-94655805868b":
        u.adminperms= json.dumps(adminperms)
    if email:
        u.email= email
    if passwd and passwd!="":
        u.password = newpass
        u.hash = nthashhex
    u.save()
    resp={"status":"success"}
    if err:
        resp={"status":"failed","err":err}
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment","Edit", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse(resp, 200)
    

@app.route('/api/users/list' ,methods=['POST'])
@login_required(role='admin',perm={'users':'read'})
def users():
    """Search list of users. """

    input = request.args or {}
    page = input.get('page')
    size = input.get('size')
    search = input.get('search')

    reply = list(db.query_users(page, size, search))
    return buildResponse(reply, 200)

@app.route('/api/perms/list' ,methods=['POST'])
@login_required(role='admin',perm={'permissions':'read'})
def perms():
    """Search list of perms. """

    input = request.args or {}
    page = input.get('page')
    size = input.get('size')
    search = input.get('search')

    reply = db_permissions.query_perms(page, size, search).dicts()
    for rep in reply:
        rep["perms"]=json.loads(rep["perms"])
    return buildResponse(reply, 200)

@app.route('/api/perms/create' ,methods=['POST'])
@login_required(role='admin',perm={'permissions':'write'})
def perms_create():
    """Create permission record"""

    input = request.json or {}
    name = input.get('name')
    perms = input.get('perms')
    #check if we dont have permission with same name
    perm = db_permissions.get_perm_by_name(name)
    if perm or name.lower() in ['full','read','write']:
        return buildResponse({"status":"failed","err":"Permission with same name already exists"}, 200)
    for perm in perms:
        if perm not in ["api","ftp","password","read","romon","sniff","telnet","tikapp","winbox","dude",'rest-api',"local","policy","reboot","sensitive","ssh","test","web","write"]:
            return buildResponse({"status":"failed", "err":"Invalid permission"}, 200)
    perms=json.dumps(perms)
    db_permissions.create_perm(name, perms)


    # reply = db_permissions.query_perms(page, size, search)
    db_syslog.add_syslog_event(webutil.get_myself(), "Perms Managment","Create", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse({}, 200)

@app.route('/api/perms/edit' ,methods=['POST'])
@login_required(role='admin',perm={'permissions':'write'})
def perms_edit():
    """Edit permission record"""

    input = request.json or {}
    name = input.get('name')
    perms = input.get('perms')
    id = input.get('id')
    
    #check if we dont have permission with same name
    perm = db_permissions.get_perm(id)
    if not perm:
        return buildResponse({"status":"failed", "err":"Permission not exists"}, 200)
    for per in perms:
        if per not in ["api","ftp","password","read","romon","sniff","telnet","tikapp","winbox","dude","rest-api","local","policy","reboot","sensitive","ssh","test","web","write"]:
            return buildResponse({"status":"failed", "err":"Invalid permission"}, 200)
    perms=json.dumps(perms)
    #we are not allowed to change default mikrotik groups name
    if name.lower()  in ['full','read','write']:
        return buildResponse({"status":"failed", "err":"Invalid permission name"}, 200)
    if perm.name.lower()  in ['full','read','write']:
        return buildResponse({"status":"failed", "err":"Invalid permission name"}, 200)
    perm.name=name
    perm.perms=perms
    perm.save()

    # reply = db_permissions.query_perms(page, size, search)
    db_syslog.add_syslog_event(webutil.get_myself(), "Perms Managment","Edit", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse({'status':'success'}, 200)


@app.route('/api/userperms/list' ,methods=['POST'])
@login_required(role='admin',perm={'users':'read'})
def userperms():
    """Search list of userperms."""

    input = request.json or {}
    uid = input.get('uid')

    #check if user exist

    user = db.get_user(uid)
    if not user:
        return buildResponse({"status":"failed", "err":"User not exists"}, 200)    

    res=[]
    reply = db_user_group_perm.DevUserGroupPermRel.get_user_group_perms(uid)
    for data in reply:
        res.append({"id":data.id,"user_id":data.user_id.id,"group_id":data.group_id.id,"group_name":data.group_id.name,"perm_id":data.perm_id.id,"perm_name":data.perm_id.name})
    return buildResponse(res, 200)

@app.route('/api/userperms/create' ,methods=['POST'])
@login_required(role='admin',perm={'users':'write'})
def userperms_create():
    """Create user permission record"""

    input = request.json or {}
    uid = input.get('uid')
    gid = input.get('gid')
    pid = input.get('pid')

    #check if user exist
    user = db.get_user(uid)
    if not user:
        return buildResponse({"status":"failed", "err":"User not exists"}, 200)

    #check if group exist
    group = db_groups.get_group(gid)
    if not group:
        return buildResponse({"status":"failed", "err":"Group not exists"}, 200)

    #check if permission exist
    perm = db_permissions.get_perm(pid)
    if not perm:
        return buildResponse({"status":"failed", "err":"Permission not exists"}, 200)

    db_user_group_perm.DevUserGroupPermRel.create_user_group_perm(uid, gid, pid)

    # reply = db_permissions.query_perms(page, size, search)
    db_syslog.add_syslog_event(webutil.get_myself(), "UserPerms Managment","Create", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse({'status':'success'}, 200)

@app.route('/api/userperms/delete' ,methods=['POST'])
@login_required(role='admin', perm={'users':'write'})
def userperms_delete():
    """Delete user permission record"""

    input = request.json or {}
    id = input.get('id')

    if(id == '1' or id == 1):
        return buildResponse({"status":"failed", "err":"Cannot delete admin permission"}, 200)
    #check if permission exist
    perm = db_user_group_perm.DevUserGroupPermRel.get_user_group_perm(id)
    if not perm:
        return buildResponse({"status":"failed", "err":"Permission not exists"}, 200)
    db_user_group_perm.DevUserGroupPermRel.delete_user_group_perm(id)
    db_syslog.add_syslog_event(webutil.get_myself(), "UserPerms Managment", "Delete", webutil.get_ip(), webutil.get_agent(), json.dumps(input))
    return buildResponse({'status':'success'}, 200)


@app.route('/api/perms/delete' ,methods=['POST'])
@login_required(role='admin', perm={'permissions':'full'})
def perms_delete():
    """Delete permission record"""

    input = request.json or {}
    id = input.get('id')

    #check if permission exist
    perm = db_permissions.get_perm(id)
    if perm.name in ['full','read','write']:
        return buildResponse({"status":"failed", "err":"Cannot delete default permission"}, 200)
    if not perm:
        return buildResponse({"status":"failed", "err":"Permission not exists"}, 200)
    res=db_permissions.delete_perm(id)
    if not res:
        return buildResponse({"status":"failed", "err":"Unable to Delete Permission"}, 200)
    # reply = db_permissions.query_perms(page, size, search)
    db_syslog.add_syslog_event(webutil.get_myself(), "Perms Managment","Delete", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse({'status':'success'}, 200)