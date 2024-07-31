#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_user_group_perm.py: Models and functions for accsessing db related to user groups relation permision
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com


from peewee import *

from libs.db.db_device import Devices
from libs.db.db import User,BaseModel,get_object_or_none
from libs.db.db_permissions import Perms
from libs.db.db_groups import DevGroups,DevGroupRel

import logging
log = logging.getLogger("db_user_group_perm")


class DevUserGroupPermRel(BaseModel):
    user_id = ForeignKeyField(User, related_name='user_id')
    group_id = ForeignKeyField(DevGroups, related_name='group_id')
    perm_id = ForeignKeyField(Perms, related_name='perm_id')

    class Meta:
        db_table = 'user_group_perm_rel'

    def __str__(self):
        return "DevUserGroupPermRel: user_id: %s, group_id: %s, perm_id: %s" % (self.user_id, self.group_id, self.perm_id)

    def __repr__(self):
        return "DevUserGroupPermRel: user_id: %s, group_id: %s, perm_id: %s" % (self.user_id, self.group_id, self.perm_id)

    def get_user_devices(uid,group_id=False):
        perms=list(DevUserGroupPermRel.select().where(DevUserGroupPermRel.user_id == uid))
        for perm in perms:
            if group_id==1 or (perm.group_id.id == 1 and not group_id):
                return Devices.select()
            elif perm.group_id.id == 1 and group_id:
                return Devices.select().join(DevGroupRel).where(DevGroupRel.group_id == group_id)
        if group_id:
            return Devices.select().join(DevGroupRel).join(DevUserGroupPermRel,on=(DevUserGroupPermRel.group_id == DevGroupRel.group_id)).where(DevUserGroupPermRel.user_id == uid, DevGroupRel.group_id == group_id)
        return Devices.select().join(DevGroupRel).join(DevUserGroupPermRel,on=(DevUserGroupPermRel.group_id == DevGroupRel.group_id)).where(DevUserGroupPermRel.user_id == uid)

    def get_user_devices_by_ids(uid,ids):
        perms=list(DevUserGroupPermRel.select().where(DevUserGroupPermRel.user_id == uid))
        for perm in perms:
            if perm.group_id.id == 1:
                return Devices.select().where(Devices.id << ids)
        return Devices.select().join(DevGroupRel).join(DevUserGroupPermRel,on=(DevUserGroupPermRel.group_id == DevGroupRel.group_id)).where(DevUserGroupPermRel.user_id == uid,Devices.id << ids)
    
    def delete_group(gid):
        #check if group exists
        group = get_object_or_none(DevGroups, id=gid)
        if group:
            try:
                #First delete records from DevGroupRel
                delete=DevGroupRel.delete().where(DevGroupRel.group_id == gid).execute()
                #delete group records from DevUserGroupPermRel
                delete=DevUserGroupPermRel.delete().where(DevUserGroupPermRel.group_id == gid).execute()
                delete=group.delete_instance(recursive=True)
                return True
            except Exception as e:
                return False
        return False


    def get_user_group_perms(uid):
        return DevUserGroupPermRel.select().where(DevUserGroupPermRel.user_id == uid)
    
    def create_user_group_perm(user_id, group_id, perm_id):
        return DevUserGroupPermRel.create(user_id=user_id, group_id=group_id, perm_id=perm_id)
    
    def query_permission_by_user_and_device_group(uid , devgrupid):
        q = DevUserGroupPermRel.select().where(DevUserGroupPermRel.group_id  << devgrupid,DevUserGroupPermRel.user_id == uid)
        return (q)
    
    def get_user_group_perm(id):
        try:
            return DevUserGroupPermRel.select().where(DevUserGroupPermRel.id == id).get()
        except:
            return False

    def delete_user_group_perm(id):
        try:
            return DevUserGroupPermRel.delete().where(DevUserGroupPermRel.id == id).execute()
        except:
            return False