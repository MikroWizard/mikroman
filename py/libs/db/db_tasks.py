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
    signal = IntegerField()
    starttime = DateTimeField()
    endtime = DateTimeField()
    status = BooleanField()
    action = TextField()
    name = TextField()
    task_id = TextField(null=True)
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'tasks'
        indexes = (
            (('signal', 'task_id'), True),
        )

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

def exec_sequence_status():
    return (Tasks.select().where(Tasks.signal == 175).get())

def get_running_tasks():
    return (Tasks.select().where(Tasks.status == True))

def get_task_by_signal(signal):
    return (Tasks.select().where(Tasks.signal == signal).get())

def get_all():
    return (Tasks.select())

def create_bulk_add_task(task_id):
    import datetime
    task = Tasks.create(
        signal=180,
        task_id=task_id,
        starttime=datetime.datetime.now(),
        endtime=datetime.datetime.now(),
        status=False,
        action='None',
        name='Bulk Add'
    )
    return task

def exec_multi_brand_status():
    return (Tasks.select().where(Tasks.signal == 185).get())

def create_exec_multi_brand_task(task_id=None):
    import datetime
    task = Tasks.create(
        signal=185,
        task_id=task_id,
        starttime=datetime.datetime.now(),
        endtime=datetime.datetime.now(),
        status=False,
        action='None',
        name='Multi-Brand Exec'
    )
    return task

def get_bulk_add_task(task_id):
    try:
        return Tasks.select().where((Tasks.signal == 180) & (Tasks.task_id == task_id)).get()
    except:
        return None

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

