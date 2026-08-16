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
        if by=='proxy' or by=='Web-Proxy':
            ts = timestamp or int(time.time())
            u_str = username.strip() if username else ''
            # Resolve the real session id (MikroWizard proxy UUID). Never fabricate a
            # 'sessionid<timestamp>' value — such rows have no recording and break playback.
            sid = str(sessionid) if (sessionid and sessionid != True) else None
            if sid and sid.startswith('sessionid'):
                sid = None

            existing = None
            # 1) Exact match on the session id (accurate link to the proxy_init row).
            if sid:
                existing = Auth.select().where(
                    (Auth.sessionid == sid) &
                    (Auth.by == 'Web-Proxy')
                ).order_by(Auth.id.desc()).first()
            # 2) Fallback: most recent Web-Proxy row for this user/device within 30s
            #    (legacy callers that don't supply a session id).
            if not existing:
                cutoff = ts - 30
                existing = Auth.select().where(
                    (Auth.devid == devid) &
                    (Auth.username == u_str) &
                    (Auth.by == 'Web-Proxy') &
                    (Auth.started >= cutoff)
                ).order_by(Auth.id.desc()).first()

            if existing:
                if sid:
                    existing.sessionid = sid
                    existing.save()
                return True

            event=Auth(
                devid=devid,
                ltype='loggedin',
                username=u_str,
                ip=ip.strip() if ip else '',
                by='Web-Proxy',
                started=ts,
                ended=0,
                sessionid=sid,
                message=message or 'proxy'
            )
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
                # -----------------------------------------------------------------
                # [COMMENTED OUT - Check 1] 2026-07-27
                # PURPOSE: Check 1 was added to prevent duplicate "Local Access" rows
                # when WebFig proxy sessions generated syslog events. When a user opened
                # WebFig via the proxy, the RADIUS accounting Start was skipped (MW-proxy),
                # so syslog events had no RADIUS row to merge with. Check 1 looked for
                # an active unclosed Web-Proxy session and suppressed the syslog event.
                #
                # WHY COMMENTED: Check 1 caused problems with Case C — when a user had
                # an active WebFig proxy session AND also made a direct WebFig/RADIUS
                # login on the same device, Check 1 incorrectly suppressed the direct
                # login's syslog event. This also could interfere with concurrent sessions.
                #
                # WHY IT STILL WORKS WITHOUT CHECK 1: The Web-Proxy Auth row created by
                # AuthPro.attach_or_create_proxy_log has ltype='loggedin' and the same
                # username, so Check 2 (15-second window) naturally finds it and merges
                # the syslog event harmlessly (doesn't overwrite by='Web-Proxy').
                # For direct logins during an active proxy session, the old proxy row
                # falls outside the 15s window, so the RADIUS accounting row is matched.
                #
                # TO REVERT: Uncomment the block below if Check 2 fails to prevent
                # duplicate sessionid=None rows for WebFig proxy sessions.
                # -----------------------------------------------------------------
                # u_clean = username.strip() if username else ''
                # b_clean = by.strip() if by else ''
                #
                # if b_clean == 'web':
                #     active_proxy = Auth.select().where(
                #         (Auth.devid == devid) &
                #         (Auth.by == 'Web-Proxy') &
                #         (Auth.username == u_clean) &
                #         ((Auth.ended.is_null(True)) | (Auth.ended == 0))
                #     ).order_by(Auth.started.desc()).first()
                #
                #     if active_proxy:
                #         log.info(f"[Auth Log] Merging syslog RADIUS login for {u_clean} via web into active Web-Proxy sessionid={active_proxy.sessionid} for devid={devid}")
                #         return True
                # -----------------------------------------------------------------

                # Check 2: Try to find matching RADIUS-created row within a 15-second window.
                auth = Auth.select().where(
                    Auth.devid == devid,
                    Auth.ltype == type,
                    Auth.username == username.strip(),
                    Auth.started > timestamp - 15,
                    Auth.started < timestamp + 15
                ).order_by(Auth.started.desc()).limit(1)
                auth_list = list(auth)
                if len(auth_list) > 0:
                    # RADIUS row exists — merge syslog connection details into it
                    a = auth_list[0]
                    if by and not a.by:
                        a.by = by.strip()
                    a.save()
                else:
                    # No RADIUS accounting row — likely a WebFig proxy login (MW-proxy
                    # accounting creates no Auth row). Link to the active Web-Proxy
                    # session instead of creating a no-sessionid row that renders as a
                    # "local" login. Only reached for message=='radius' (non-local).
                    active_proxy = Auth.select().where(
                        (Auth.devid == devid) &
                        (Auth.username == username.strip()) &
                        (Auth.by == 'Web-Proxy') &
                        ((Auth.ended.is_null(True)) | (Auth.ended == 0))
                    ).order_by(Auth.started.desc()).first()
                    if active_proxy:
                        return True
                    # Genuine RADIUS login whose accounting hasn't arrived yet — create row.
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
            if by == 'Web-Proxy' or by == 'proxy':
                return
            if sessionid:
                Auth.update(ended = timestamp).where((Auth.sessionid==sessionid) & (Auth.by != 'Web-Proxy')).execute()
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
                        (Auth.ended.is_null(True) | (Auth.ended == 0)),
                        (Auth.by != 'Web-Proxy') & (Auth.by != 'proxy')
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



