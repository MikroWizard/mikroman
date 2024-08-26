#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_group.py: Models and functions for accsessing db related to Device groups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db import User,BaseModel,get_object_or_none
import logging
from libs.db.db_device import Devices
log = logging.getLogger("db_groups")


class DevGroups(BaseModel):
    name = TextField()
    owner = ForeignKeyField(db_column='owner', null=True,
                    model=User, to_field='id')
    created = DateTimeField()
    modified = DateTimeField()

    class Meta:
        db_table = 'device_groups'

def get_group(id):
    return get_object_or_none(DevGroups, id=id)

class DevGroupRel(BaseModel):
    group_id = ForeignKeyField(db_column='group_id', null=True,
                    model=DevGroups, to_field='id')
    device_id = ForeignKeyField(db_column='device_id', null=True,
                    model=Devices, to_field='id')
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'device_groups_devices_rel'
        indexes = (
            # Specify a unique multi-column index on from/to-user.
            (('group_id', 'device_id'), True),
        )

def create_group(name):
    try:
        #check if we have a group with same name
        group = get_object_or_none(DevGroups,name=name)
        #if we do, return id
        if group:
            return False
        group = DevGroups.create(name=name)
    except IntegrityError:
        return False
    return group
    
def update_group(id, name):
    group = get_group(id)
    group.name = name
    group.save()
    return group

def add_devices_to_group(group, devids):
    data=[]
    for devid in devids:
        data.append({'group_id': group, 'device_id': devid})
    res=DevGroupRel.insert_many(data).on_conflict_ignore().execute()
    return res

#Get groups of device
def devgroups(devid):
    return (DevGroups
            .select()
            .join(DevGroupRel, on=DevGroupRel.group_id)
            .where(DevGroupRel.device_id == devid)
            .order_by(DevGroups.name))

#Get devices of group
def devs(groupid):
    return (Devices
            .select()
            .join(DevGroupRel, on=DevGroupRel.device_id)
            .where(DevGroupRel.group_id == groupid)
            .order_by(Devices.name))

#Get groups of device
def devgroups_api(devid):
    return list(DevGroups
            .select()
            .join(DevGroupRel, on=DevGroupRel.group_id)
            .where(DevGroupRel.device_id == devid)
            .order_by(DevGroups.name).dicts())

#Get devices of group in dict
def devs(groupid):
    return list(Devices
            .select()
            .join(DevGroupRel, on=DevGroupRel.device_id)
            .where(DevGroupRel.group_id == groupid)
            .order_by(Devices.name).dicts())

#Get devices of group
def devs2(groupid):
    return list(Devices
            .select()
            .join(DevGroupRel, on=DevGroupRel.device_id)
            .where(DevGroupRel.group_id == groupid)
            .order_by(Devices.name))
def get_devs_of_groups(group_ids):
    try:
        group_ids=[group.id for group in group_ids]
        if 1 in group_ids:
            return list(Devices
                .select()
            .order_by(Devices.name))
        return list(Devices
            .select()
            .join(DevGroupRel, on=DevGroupRel.device_id)
            .where(DevGroupRel.group_id << group_ids)
            .order_by(Devices.name))
    except Exception as e :
        log.error(e)
        return []
        
#get all groups including devices in each group
def query_groups_api():
    t3=DevGroups.alias()
    q=DevGroups.select(DevGroups.id,DevGroups.name,DevGroups.created,fn.array_agg(DevGroupRel.device_id)).join(DevGroupRel,JOIN.LEFT_OUTER, on=(DevGroupRel.group_id == DevGroups.id)).order_by(DevGroups.id).group_by(DevGroups.id)
    return list(q.dicts())

def get_groups_by_id(ids):
    """Return list of unique directors. An example of a raw SQL query."""
    q=DevGroups.select().where(DevGroups.id << ids)
    try:
        q=list(q)
    except Exception as e :
        log.error(e)
        q=False
    return q

def delete_from_group(devids):
    delete=DevGroupRel.delete().where(DevGroupRel.device_id << devids).execute()
    return delete

def delete_device(devid):
    try:

        delete_from_group([devid])
        dev = get_object_or_none(Devices, id=devid)
        dev.delete_instance(recursive=True)
        return True
    except Exception as e:
        log.error(e)
        return False


# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


