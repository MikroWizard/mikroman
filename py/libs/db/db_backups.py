#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_backups.py: Models and functions for accsessing db related to backups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db_device import Devices
from libs.db.db import User,BaseModel,get_object_or_404,database
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
    q = q.paginate(page, limit).order_by(Backups.id.desc())
    return q

# The run (command_execution_log row) that stored a backup row's raw file: same device, same
# file, nearest in time (row and log are written in the same transaction; the 1-day window
# keeps the lookup on the (device_id, executed_at) index). Unchanged configurations share one
# raw file, so "the newest run with this file" would label old rows with later runs.
_RUN_OF_BACKUP_SQL = (
    "SELECT b.id, (SELECT l.id FROM command_execution_log l"
    "  WHERE l.device_id = b.devid"
    "  AND l.executed_at BETWEEN b.created - interval '1 day' AND b.created + interval '1 day'"
    "  AND l.raw_storage_path = substring(b.dir from '(raw/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{64}\\.txt)$')"
    "  ORDER BY abs(extract(epoch FROM (l.executed_at - b.created))), l.id DESC LIMIT 1)"
    " FROM backups b WHERE b.id = ANY(%s)")


def runs_of_backups(backup_ids):
    """{backup id: execution log id or None} for backup rows that point to a raw blob."""
    found = {}
    ids = list(backup_ids)
    for i in range(0, len(ids), 1000):
        found.update(dict(database.execute_sql(_RUN_OF_BACKUP_SQL, (ids[i:i + 1000],)).fetchall()))
    return found


def create(dev,directory,size):
    backup=Backups(devid=dev.id,dir=directory,filesize=size)
    backup.save()
# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)
