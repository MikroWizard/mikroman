#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_events.py: Models and functions for accsessing db related to Events
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *
 
from libs.db.db_device import Devices
from libs.db.db import BaseModel

import logging
log = logging.getLogger("db_events")

from playhouse.postgres_ext import  BooleanField

class Events(BaseModel):
    devid = ForeignKeyField(db_column='devid', null=True, model=Devices, to_field='id')
    eventtype = TextField()
    detail = TextField()
    level = TextField()
    src = TextField()
    eventtime = DateTimeField()
    status = BooleanField()
    comment = TextField()
    fixtime = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'events'

def get_events_by_src_and_status(src, status,devid):
    return Events.select().where(Events.src==src, Events.status==status, Events.devid==devid)

def fix_event(id):
    event=Events.get(Events.id==id)
    event.update(status=1,fixtime='NOW').where(Events.id==event.id).execute()

def connection_event(devid,src,detail,level,status=0,comment=""):
    #check if we have same event for device before adding new one
        event=Events.select().where(
            Events.devid==devid, 
            Events.eventtype=="connection", 
            Events.src==src, 
            Events.detail==detail, 
            Events.level==level, 
            Events.status==False)
        if not event and not status:
            event=Events(devid=devid, eventtype="connection", detail=detail, level=level, src=src, status=status ,comment=comment)
            event.save()
        elif event and status:
            list(event)[0].update(status=status).execute()

def config_event(devid,src,detail,level,status=0,comment=""):
    #check if we have same event for device before adding new one
    event=Events.select().where(
        Events.devid==devid, 
        Events.eventtype=="config", 
        Events.src==src, 
        Events.detail==detail, 
        Events.level==level,
        Events.status==False)
    if not event and not status:
        event=Events(devid=devid, eventtype="config", detail=detail, level=level, src=src, status=status, comment=comment)
        event.save()
    elif event and status:
        list(event)[0].update(status=status).execute()



def firmware_event(devid,src,detail,level,status=0,comment=""):
    #check if we have same event for device before adding new one
    event=Events.select().where(
        Events.devid==devid, 
        Events.eventtype=="firmware", 
        Events.src==src, 
        Events.detail==detail, 
        Events.level==level,
        Events.status==False)
    if not event and not status:
        event=Events(devid=devid, eventtype="firmware", detail=detail, level=level, src=src, status=status, comment=comment)
        event.save()
    elif event and status:
        list(event)[0].update(status=status).execute()

def health_event(devid, src, detail, level, status=0, comment=""):
    #check if we have same event for device before adding new one
    event=Events.select().where(
        Events.devid==devid,
        Events.eventtype=="health",
        Events.src==src,
        Events.detail==detail,
        Events.level==level,
        Events.status==False)
    if not event and not status:
        event=Events(devid=devid, eventtype="health", detail=detail, level=level, src=src, status=status, comment=comment)
        event.save()
    elif event and status:
        list(event)[0].update(status=status).execute()

def state_event(devid, src, detail, level, status=0, comment=""):
    #check if we have same event for device before adding new one
    event=Events.select().where(
        Events.devid==devid,
        Events.eventtype=="state",
        Events.src==src,
        Events.detail==detail,
        Events.level==level,
        Events.status==False)
    if not event and not status:
        event=Events(devid=devid, eventtype="state", detail=detail, level=level, src=src, status=status, comment=comment)
        event.save()
    elif event and status:
        list(event)[0].update(status=status).execute()
    elif not event and status:
        event=Events(devid=devid, eventtype="state", detail=detail, level=level, src=src, status=status, comment=comment)
        event.save()

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)
