#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_sysconfig.py: Models and functions for accsessing db related to mikrowizard system configs
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db import User,BaseModel,get_object_or_404
import logging
log = logging.getLogger("db_sysconfig")

class Sysconfig(BaseModel):

    #id - automatic

    key = TextField()
    value = TextField()

    created_by = ForeignKeyField(db_column='created_by', null=True,
                    model=User, to_field='id')
    created = DateTimeField()
    modified = DateTimeField()

    class Meta:
        db_table = 'sysconfig'

def get_default_user():
    return get_object_or_404(Sysconfig, key="default_user")

def get_all():
    return Sysconfig.select()

def save_all(data):
    Sysconfig.insert_many(data).on_conflict(conflict_target=['key'], preserve=(Sysconfig.value,Sysconfig.modified)).execute()

def get_default_password():
    return get_object_or_404(Sysconfig, key="default_password")
def update_sysconfig(key,value):
    return Sysconfig.update(value=value).where(Sysconfig.key == key).execute()

def get_scan_mode():
    return get_object_or_404(Sysconfig, key="scan_mode")

def get_sysconfig(key):
    return get_object_or_404(Sysconfig, key=key).value

def get_firmware_latest():
    return get_object_or_404(Sysconfig, key="latest_version")

def get_firmware_action():
    return get_object_or_404(Sysconfig, key="old_firmware_action")

def get_firmware_old():
    return get_object_or_404(Sysconfig, key="old_version")

def get_mac_scan_interval():
    return get_object_or_404(Sysconfig, key="mac_scan_interval")

def get_ip_scan_interval():
    """Return Movie or throw."""
    return get_object_or_404(Sysconfig, key="ip_scan_interval")

def update_sysconfig(key,value):
    return Sysconfig.insert(value=value,key=key).on_conflict(conflict_target=['key'], preserve=['key'], update={'value':value}).execute()                        # firm.version = version

def set_sysconfig(key,value):
    return Sysconfig.insert(value=value, key=key).on_conflict(conflict_target=['key'], preserve=['key'], update={'value':value}).execute()                        # firm.version = version


# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


