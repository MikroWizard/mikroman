#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_syslog.py: Models and functions for accsessing db related to mikrowizard internal logs
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db import User,BaseModel

import logging
log = logging.getLogger("db_syslog")


# --------------------------------------------------------------------------
# this model contains two foreign keys to user -- it essentially allows us to
# model a "many-to-many" relationship between users.  by querying and joining
# on different columns we can expose who a user is "related to" and who is
# "related to" a given user
class SysLog(BaseModel):
    user_id = ForeignKeyField(db_column='user_id', null=True, model=User, to_field='id')
    action = TextField()
    section = TextField()
    ip = TextField()
    agent = TextField()
    data = TextField()
    created = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'syslogs'


def add_syslog_event(user_id,section,action,ip,agent,data):
    event=SysLog(user_id=user_id, section=section, action=action,ip=ip,agent=agent, data=data)
    event.save()

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


