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
        if type=='failed':
            rand=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
            auth=Auth.select().where(Auth.ltype==type, Auth.username==username.strip())
            if message=='radius':
                count=0
                while(len(list(auth))<1 and count<33):
                    auth=auth.where(Auth.started > timestamp-2,Auth.started < timestamp+2)
                    time.sleep(0.3)
                    count+=1
            else:
                auth=False
            if auth:
                count=1
                for a in auth:
                    if by:
                        a.by=by.strip()
                        a.sessionid=str(timestamp+count)+rand
                    count+=1
                    a.save()
            else:
                if by:
                    by=by.strip()
                event=Auth(devid=int(devid), ltype=type, username=username.strip(), ip=ip.strip(), by=by,started=timestamp, ended=timestamp, message=message)
                event.save()
        elif type=='loggedin':
            auth=Auth.select().where(Auth.devid==devid, Auth.ltype==type, Auth.username==username.strip())
            if sessionid:
                auth=auth.where(Auth.sessionid==sessionid)
            else:
                if message=='radius':
                    auth=auth.where(Auth.started > timestamp-2,Auth.started < timestamp+2)
                    count=0
                    while(len(list(auth))<1 and count<33):
                        auth=auth.where(Auth.started > timestamp-2,Auth.started < timestamp+2)
                        time.sleep(0.3)
                        count+=1
                else:
                    auth=False
            if auth and len(list(auth))>0:
                auth=list(auth)
                for a in auth:
                    if sessionid and not a.sessionid:
                        a.sessionid=sessionid
                    if by:
                        a.by=by.strip()
                    if message:
                        a.message=message
                    a.save()
            else:
                if not sessionid:
                    sessionid=None
                if by:
                    by=by.strip()
                event=Auth(devid=devid,ltype=type,username=username.strip(),ip=ip.strip(),by=by,started=timestamp,sessionid=sessionid,message=message)
                event.save()
        else:
            if sessionid:
                Auth.update(ended = timestamp).where(Auth.sessionid==sessionid).execute()
            else:
                #check if we have same record with type loggedout and same timestamp and same username and if there is not create one
                if message=='radius':
                    pass
                else:
                    event=Auth(devid=devid, ltype=type, username=username.strip(), ip=ip.strip(), by=by.strip(), ended=timestamp,message=message)
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

 
