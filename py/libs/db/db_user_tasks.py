#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_user_tasks.py: Models and functions for accsessing db related to user tasks
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *
from libs.db.db_device import Devices
from libs.db.db import User,BaseModel,get_object_or_none
from libs.db.db_groups import DevGroups,get_devs_of_groups
import logging
log = logging.getLogger("db_user_tasks")


class Snippets(BaseModel):

    name = TextField()
    description = TextField()
    content = TextField()
    created = DateTimeField()

    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'snippets'

def get_snippet_by_name(name):
    return get_object_or_none(Snippets, name=name)

def get_snippet(id):
    return get_object_or_none(Snippets, id=id)

def update_snippet(id,name, description, content):
    snippet = get_object_or_none(Snippets, id=id)
    snippet.name = name
    snippet.description = description
    snippet.content = content
    snippet.save()

def create_snippet(name, description, content):
    snippet = Snippets()
    snippet.name = name
    snippet.description = description
    snippet.content = content
    snippet.save()

def delete_snippet(id):
    snippet = get_object_or_none(Snippets, id=id)
    snippet.delete_instance()

class UserTasks(BaseModel):

    name = TextField()
    description = TextField()
    desc_cron = TextField()
    dev_ids = TextField()
    snippetid = ForeignKeyField(db_column='snippetid', null=True,
                    model=Snippets, to_field='id')
    data = TextField()
    cron = TextField()
    action = TextField()
    task_type = TextField()
    selection_type = TextField()
    created = DateTimeField()

    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'user_tasks'

    def get_utask_by_id(tid):
        return get_object_or_none(UserTasks, id=tid)

class TaskDevRel(BaseModel):
    utask_id = ForeignKeyField(UserTasks, related_name='utask_id')
    group_id = ForeignKeyField(DevGroups, related_name='group_id')
    device_id = ForeignKeyField(Devices, related_name='device_id')

    class Meta:
        db_table = 'task_group_dev_rel'

def get_task_devices(task,return_devs=True):
    members=[]
    members=list(TaskDevRel.select().where(TaskDevRel.utask_id == task.id).execute())
    devs=[]
    if task.selection_type=='groups':
        group_ids=[]
        for mem in members:
            try:
                group_ids.append(mem.group_id)
            except DoesNotExist as err:
                log.error(err)
                pass
        if return_devs:
            devs=get_devs_of_groups(group_ids)
        else:
            devs=group_ids
    else:
        for mem in members:
            try:
                devs.append(mem.device_id)
            except DoesNotExist as err:
                pass
    return devs

def add_member_to_task(task_id,members,type='devices'):
    data=[]
    for member in members:
        if type=='groups':
            data.append({'utask_id': task_id, 'group_id': member})
        else:
            data.append({'utask_id': task_id, 'device_id': member})
    res=TaskDevRel.insert_many(data).on_conflict_ignore().execute()
    return res

def delete_members(task_id):
    res=TaskDevRel.delete().where(TaskDevRel.utask_id == task_id).execute()
    return res
# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


