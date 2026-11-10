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
import uuid
import datetime
from libs import webutil,account,user_guard,login_throttle
from libs.webutil import app, login_required, get_myself , buildResponse
from libs.mschap3.mschap import nt_password_hash
try:
    from libs import utilpro
    from libs.db.db_tickets_pro import UserActivationToken_pro
    from libs.mail_pro import send_activation_email
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
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

    # failed-login throttling (per IP + username and per IP); fail-open without Redis
    client_ip = webutil.get_ip()
    rds = app.config.get("SESSION_REDIS")
    wait = login_throttle.blocked_for(rds, client_ip, username)
    if wait:
        mins = max(1, (wait + 59) // 60)
        return buildResponse({"status":"failed",
                              "err":"Too many failed login attempts. Try again in {} minute(s).".format(mins)}, 200)

    u = db.get_user_by_username(username)
    # unknown user: still run one password hash check, so the reply time does not reveal
    # whether the username exists
    password_ok = account.check_password(u.password, password) if u else account.check_password(account.DUMMY_HASH, password)
    if not u or not password_ok or u.role in ['disabled', 'customer_inactive']:
        # error
        login_throttle.failure(rds, client_ip, username)
        try:
            db_syslog.add_syslog_event(u.id if u else None, "User login","Failed login",webutil.get_ip(),webutil.get_agent(),json.dumps({"username":username,'reason':'wrong password' if u else 'unknown user'}))
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
                if isinstance(prores, dict) and prores.get("status") == "failed":
                    login_throttle.failure(rds, client_ip, username)     # wrong OTP
                elif isinstance(prores, dict) and prores.get("uid"):
                    login_throttle.success(rds, client_ip, username)     # logged in (OTP ok / no OTP)
                return buildResponse(prores, 200)
        account.build_session(u, is_permanent=input.get('remember', True))
        login_throttle.success(rds, client_ip, username)
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

    # no role / permission above the creator's own (superuser and the default admin: no limit)
    me = get_myself()
    guard_err = user_guard.check_assign_role(me, role, webutil.GUARDED_ADMIN_ID)
    if guard_err:
        return buildResponse({"status":"failed","err":guard_err}, 200)
    adminperms, capped = user_guard.cap_perms(me, adminperms, webutil.GUARDED_ADMIN_ID)
    if capped:
        log.warning("create_user: permissions capped to the creator's level: {}".format(capped))

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
    if role == 'customer':
        if email and email.strip():
            u.role = 'customer_inactive'
        else:
            u.role = 'customer'
    else:
        u.role = role
    u.save(force_insert=True)
    account.new_signup_steps(u)

    if u.role == 'customer_inactive' and ISPRO:
        try:
            token = str(uuid.uuid4())
            expires = datetime.datetime.now() + datetime.timedelta(hours=24)
            UserActivationToken_pro.create(user_id=u.id, token=token, type='activation', expires=expires)
            domain_url = request.host_url
            send_activation_email(u, token, domain_url)
        except Exception as e:
            log.error("Failed to generate/send activation token: {}".format(e))
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
    guard_err = user_guard.check_target(get_myself(), u, webutil.GUARDED_ADMIN_ID)
    if guard_err:
        return buildResponse({"status":"failed","err":guard_err}, 200)

    u.delete_instance(recursive=True)
    if ISPRO:
        try:
            utilpro.revoke_user_pam(uid)
        except Exception as e:
            log.error("revoke pam on delete error: {}".format(e))
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
        nthashhex=''.join(list("{:02x}".format(ord(c)) for c in nt_password_hash(newpass)))
        newpass = account.hash_password(newpass)
    else:
        err = "Invalid password : {}".format(err)
        resp={"status":"failed","err":err}
        return buildResponse(resp, 200)

    u.password = newpass
    
    u.hash = nthashhex
    u.save()
    webutil.session_password_changed(u)   # this session stays, other sessions of the user end
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
        if ISPRO:
            try:
                status = utilpro.check_license_status()
                if status['reason'] in ('mikrotik_limit', 'other_limit'):
                    lstatus = 'over_limit'
                elif status['reason'] == 'expired':
                    lstatus = 'expired'
                elif status['reason'] == 'invalid':
                    lstatus = 'invalid'
                else:
                    lstatus = 'ok'
                res['license'] = {
                    'status': lstatus,
                    'reason': status['reason'],
                    'counts': status['counts'],
                    'limits': status['limits'],
                    'expiration': status['expiration'].isoformat() if status['expiration'] else None,
                }
            except Exception as e:
                log.error("me license status error: {}".format(e))
                res['license'] = {'status': 'ok', 'reason': None}
        else:
            res['license'] = {'status': 'free', 'reason': None}
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

    # no escalation (superuser and the default admin: no limit). The guarded default admin's
    # role / permissions stay untouchable as before (checked below).
    me = get_myself()
    if user_guard.keeps_own_role(me, u, webutil.GUARDED_ADMIN_ID):
        role, adminperms = None, None       # own role / permissions are not changed
    guard_err = (user_guard.check_target(me, u, webutil.GUARDED_ADMIN_ID)
                 or (str(u.id) != webutil.GUARDED_ADMIN_ID
                     and user_guard.check_assign_role(me, role, webutil.GUARDED_ADMIN_ID)))
    if guard_err:
        return buildResponse({"status":"failed","err":guard_err}, 200)
    adminperms, capped = user_guard.cap_perms(me, adminperms, webutil.GUARDED_ADMIN_ID)
    if capped:
        log.warning("user_edit: permissions capped to the editor's level: {}".format(capped))
    if username:
        u.username = username
    if fname:
        u.first_name = fname

    if lname:
        u.last_name = lname

    send_activation = False
    if role and str(u.id) != "37cc36e0-afec-4545-9219-94655805868b":
        if role == 'customer':
            if email and email.strip() and u.role not in ['customer', 'customer_inactive']:
                u.role = 'customer_inactive'
                send_activation = True
            elif not email or not email.strip():
                u.role = 'customer'
            else:
                u.role = role
        else:
            u.role = role
    if adminperms and str(u.id) != "37cc36e0-afec-4545-9219-94655805868b":
        u.adminperms= json.dumps(adminperms)
    if email:
        if u.role == 'customer' and email.strip() != u.email:
            u.role = 'customer_inactive'
            send_activation = True
        u.email = email
    if passwd and passwd!="":
        u.password = newpass
        u.hash = nthashhex
    u.save()
    if passwd and passwd!="":
        webutil.session_password_changed(u)   # editing yourself keeps your own session

    # Deactivation revokes PAM access (free the seat + kill active terminal sessions)
    if ISPRO and u.role == 'disabled':
        try:
            utilpro.revoke_user_pam(uid)
            db_syslog.add_syslog_event(webutil.get_myself(), "User Managment", "PAM Access Revoked", webutil.get_ip(), webutil.get_agent(), json.dumps({'uid': str(uid)}))
        except Exception as e:
            log.error("revoke pam on deactivate error: {}".format(e))

    if send_activation and u.role == 'customer_inactive' and ISPRO:
        try:
            token = str(uuid.uuid4())
            expires = datetime.datetime.now() + datetime.timedelta(hours=24)
            UserActivationToken_pro.delete().where(UserActivationToken_pro.user_id == u.id, UserActivationToken_pro.type == 'activation').execute()
            UserActivationToken_pro.create(user_id=u.id, token=token, type='activation', expires=expires)
            domain_url = request.host_url
            send_activation_email(u, token, domain_url)
        except Exception as e:
            log.error("Failed to generate/send activation token in edit: {}".format(e))
    resp={"status":"success"}
    if err:
        resp={"status":"failed","err":err}
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment","Edit", webutil.get_ip(),webutil.get_agent(),json.dumps(input))
    return buildResponse(resp, 200)
    

@app.route('/api/user/login_locks', methods=['POST'])
@login_required(role='admin', perm={'users':'read'})
def user_login_locks():
    """Current panel login lockouts (failed-login throttling)."""
    locks = login_throttle.list_locks(app.config.get("SESSION_REDIS"))
    return buildResponse({"status":"success", "locks": locks}, 200)


@app.route('/api/user/unlock_login', methods=['POST'])
@login_required(role='admin', perm={'users':'write'})
def user_unlock_login():
    """Unlock failed-login throttling for a username (all IPs) and/or an IP, for the panel
    and RADIUS (router / terminal logins). {"username": "...", "ip": "..."} or {"all": true}"""
    input = request.json or {}
    username = (input.get('username') or '').strip()
    ip = (input.get('ip') or '').strip()
    everything = input.get('all') is True
    if not username and not ip and not everything:
        return buildResponse({"status":"failed", "err":"username or ip required"}, 200)
    try:
        removed = login_throttle.unlock(app.config.get("SESSION_REDIS"), username=username or None,
                                        ip=ip or None, everything=everything)
    except Exception as e:
        log.error("unlock_login failed: {}".format(e))
        return buildResponse({"status":"failed", "err":"Unlock failed"}, 200)
    db_syslog.add_syslog_event(webutil.get_myself(), "User Managment", "Unlock Login", webutil.get_ip(),
                               webutil.get_agent(), json.dumps({"username": username, "ip": ip, "all": everything}))
    return buildResponse({"status":"success", "removed": removed}, 200)


@app.route('/api/users/list' ,methods=['POST'])
@login_required(role='admin',perm={'users':'read'})
def users():
    """Search list of users. """

    input = request.json or {}
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