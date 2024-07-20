#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_backups.py: Models and functions for accsessing db related to backups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db_device import Devices
from libs.db.db import User,BaseModel,get_object_or_404
import datetime
import logging
log = logging.getLogger("db_backup")
    

class Backups(BaseModel):
    devid = ForeignKeyField(db_column='devid', null=True, model=Devices, to_field='id')
    dir = TextField()
    filesize = IntegerField()
    created = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'backups'

def get_backup(id):
    return get_object_or_404(Backups, id=id)

def query_backup_jobs(page=0, limit=1000, search=None , devid=False):
    page = int(page or 0)
    limit = int(limit or 1000)
    q = Backups.select()
    if search:
        search = "%"+search+"%"
        q = q.where(Backups.dir ** search)
    if devid:
        q = q.where(Backups.devid == devid) 
    start_time=datetime.datetime.now()-datetime.timedelta(days=3)
    q = q.where(Backups.created >= start_time)
    q = q.paginate(page, limit).order_by(Backups.id.desc())
    return q

def create(dev,directory,size):
    backup=Backups(devid=dev.id,dir=directory,filesize=size)
    backup.save()
# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)
