#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_tasks.py: Models and functions for accsessing db related to mikrowizard internal logs
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db import User,BaseModel

import logging
log = logging.getLogger("db_tasks")

class Tasks(BaseModel):
    signal = TextField()
    starttime = DateTimeField()
    endtime = DateTimeField()
    status = BooleanField()

    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'tasks'

#Get groups of device
def update_check_status():
    return (Tasks.select().where(Tasks.signal == 100).get())

#Get groups of device
def update_job_status():
    return (Tasks.select().where(Tasks.signal == 110).get())


#Get groups of device
def backup_job_status():
    return (Tasks.select().where(Tasks.signal == 120).get())

#check status of scanner 
def scanner_job_status():
    return (Tasks.select().where(Tasks.signal == 130).get())

#check status of downloader 
def downloader_job_status():
    return (Tasks.select().where(Tasks.signal == 140).get())

def firmware_service_status():
    return (Tasks.select().where(Tasks.signal == 150).get())

def exec_snipet_status():
    return (Tasks.select().where(Tasks.signal == 160).get())


class TaskResults(BaseModel):
    task_type = TextField()
    result = DateTimeField()
    info = TextField()
    external_id = IntegerField()
    created = DateTimeField()

    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'task_results'

def add_task_result(task_type,result,info=None,eid=None):
    tr = TaskResults(task_type=task_type, result=result,info=info,external_id=eid)
    tr.save()

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)

