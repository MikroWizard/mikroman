#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_snippet.py: Models and functions for accsessing db related to auth and acc
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com


from calendar import c
from itertools import count
from peewee import *

from libs.db.db_device import Devices
from libs.db.db import User,BaseModel
import time
import logging
log = logging.getLogger("db_AA")

import random
import string
# --------------------------------------------------------------------------
# this model contains two foreign keys to user -- it essentially allows us to
# model a "many-to-many" relationship between users.  by querying and joining
# on different columns we can expose who a user is "related to" and who is
# "related to" a given user
class Auth(BaseModel):
    devid = ForeignKeyField(db_column='devid', null=True, model=Devices, to_field='id')
    ltype = TextField()
    username = TextField()
    ip = TextField()
    sessionid = TextField()
    by = TextField()
    started=BigIntegerField()
    ended=BigIntegerField()
    message=TextField()
    created = DateTimeField()

    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'auth'

    def add_log(devid,type,username,ip,by,sessionid=False,timestamp=False,message=None):
        log.error(f"DEBUG add_log ENTRY: devid={devid}, type={type}, username={username}, ip={ip}, by={by}, sessionid={sessionid}, timestamp={timestamp}, message={message}")
        if by=='proxy':
            event=Auth(devid=devid,ltype='loggedin',username=username.strip(),ip=ip.strip(),by='Web-Proxy',started=timestamp,ended=timestamp,sessionid='sessionid'+str(timestamp),message='proxy')
            event.save()
            return True
        if type=='failed':
            rand=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
            if message=='radius':
                # Syslog detected a radius-user failure. Try to find the matching
                # row that radius.py already created within a 5-second window.
                auth=Auth.select().where(
                    Auth.ltype==type,
                    Auth.username==username.strip(),
                    Auth.started > timestamp-5,
                    Auth.started < timestamp+5
                )
                auth_list=list(auth)
                if len(auth_list)>0:
                    count=1
                    for a in auth_list:
                        if by:
                            a.by=by.strip()
                            a.sessionid=str(timestamp+count)+rand
                        count+=1
                        a.save()
                    return
            # No matching row found, or non-radius failure: create new row
            if by:
                by=by.strip()
            event=Auth(devid=int(devid), ltype=type, username=username.strip(), ip=ip.strip(), by=by,started=timestamp, ended=timestamp, message=message)
            event.save()
        elif type=='loggedin':
            if message=='radius' and not sessionid:
                # Syslog event for a RADIUS user login.
                # Syslog has connection method (by='winbox'/'ssh'/etc) but no sessionid.
                # Try to find the matching RADIUS-created row within a 5-second window.
                auth = Auth.select().where(
                    Auth.devid == devid,
                    Auth.ltype == type,
                    Auth.username == username.strip(),
                    Auth.started > timestamp - 5,
                    Auth.started < timestamp + 5
                ).order_by(Auth.started.desc()).limit(1)
                auth_list = list(auth)
                if len(auth_list) > 0:
                    # RADIUS row exists — merge syslog connection details into it
                    a = auth_list[0]
                    if by and not a.by:
                        # Only set 'by' if the row doesn't already have one
                        # (e.g. MW-proxy set by accounting should not be overwritten)
                        a.by = by.strip()
                    a.save()
                else:
                    # RADIUS hasn't arrived yet — create row with connection details.
                    # RADIUS will merge its sessionid into this row when it arrives.
                    if by:
                        by = by.strip()
                    event = Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by, started=timestamp, message=message)
                    event.save()
                return

            if sessionid:
                # RADIUS accounting login (has sessionid but no connection details).
                # Find any row for this login event within 5 seconds (syslog or first RADIUS packet).
                auth = Auth.select().where(
                    Auth.devid == devid,
                    Auth.ltype == type,
                    Auth.username == username.strip(),
                    Auth.started > timestamp - 5,
                    Auth.started < timestamp + 5
                ).order_by(Auth.started.desc()).limit(1)
                auth_list = list(auth)
                if len(auth_list) > 0:
                    a = auth_list[0]
                    if a.sessionid and a.sessionid != sessionid:
                        # Winbox opens multiple sessions concurrently; we already recorded one of them.
                        # Ignore extra session packets to prevent duplicate rows.
                        return
                    try:
                        a.sessionid = sessionid
                        a.save()
                    except Exception:
                        # Sessionid already used by an old session.
                        # Rename old session's id to free the constraint, then retry.
                        Auth.update(sessionid=sessionid + '_ended').where(Auth.sessionid == sessionid).execute()
                        a.sessionid = sessionid
                        a.save()
                    return
                # No syslog row found — create new row with sessionid
                try:
                    event = Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by, started=timestamp, sessionid=sessionid, message=message)
                    event.save()
                except Exception:
                    # Sessionid already used by an old session.
                    # Rename old session's id to free the constraint, then insert new.
                    Auth.update(sessionid=sessionid + '_ended').where(Auth.sessionid == sessionid).execute()
                    event = Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by, started=timestamp, sessionid=sessionid, message=message)
                    event.save()
            else:
                # Local login from syslog (message='local', no sessionid)
                if by:
                    by = by.strip()
                event = Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by, started=timestamp, message=message)
                event.save()
        else:
            if sessionid:
                Auth.update(ended = timestamp).where(Auth.sessionid==sessionid).execute()
            else:
                if message=='radius':
                    pass
                else:
                    # Local syslog logout: find the most recent unclosed login
                    # for this user/device/ip (LIFO matching for concurrent sessions)
                    unclosed = Auth.select().where(
                        Auth.devid == devid,
                        Auth.ltype == 'loggedin',
                        Auth.username == username.strip(),
                        Auth.ip == ip.strip(),
                        Auth.ended.is_null(True)
                    ).order_by(Auth.started.desc()).limit(1)
                    unclosed_list = list(unclosed)
                    if len(unclosed_list) > 0:
                        Auth.update(ended=timestamp).where(Auth.id == unclosed_list[0].id).execute()
                    else:
                        # Fallback: no matching unclosed login found
                        if by:
                            by=by.strip()
                        event=Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by, ended=timestamp,message=message)
                        event.save()

class Account(BaseModel):
    devid = ForeignKeyField(db_column='devid', null=True, model=Devices, to_field='id')
    username  = TextField()
    action = TextField()
    section = TextField()
    message = TextField()
    ctype = TextField()
    address = TextField()
    config = TextField()
    created = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'account'

    def add_log(devid,section,action,username,message,ctype="unknown",address="unknown",config="unknown"):
        event=Account(devid=devid,section=section.strip(),action=action.strip(),message=message.strip(),username=username.strip(),ctype=ctype.strip(),address=address.strip(),config=config.strip())
        # print(event.query())
        event.save()

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


