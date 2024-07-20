#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_device.py: Models and functions for accsessing db related to devices
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *
from libs.db.db import User,BaseModel,database

import logging
from playhouse.postgres_ext import  BooleanField
log = logging.getLogger("db")


class Devices(BaseModel):

    #id - automatic

    name = TextField()
    ip = TextField()
    mac = TextField()
    details = TextField()
    uptime = TextField()
    license = TextField()
    interface = TextField()
    user_name = TextField()
    password = TextField()
    port = TextField()
    update_availble = BooleanField()
    current_firmware = TextField()
    arch = TextField()
    sensors = TextField()
    router_type = TextField()
    wifi_config = TextField()
    upgrade_availble = BooleanField()
    owner = ForeignKeyField(db_column='owner', null=True, model=User, to_field='id')
    created = DateTimeField()
    modified = DateTimeField()
    peer_ip = TextField()
    failed_attempt = IntegerField()
    status = TextField()
    firmware_to_install = TextField()
    syslog_configured = BooleanField()
    
    class Meta:
        db_table = 'devices'

def get_device(id):
    q=Devices.select().where(Devices.id == id).dicts().get()
    return q

def get_devices(ids):
    q=list(Devices.select().where(Devices.id << ids))
    return q

def query_device_by_mac(mac):
    q=Devices.select()
    try:
        q=q.where(Devices.serial == mac).get()
    except:
        q=False

    return q

def query_device_by_ip(ip):
    q=Devices.select()
    try:
        q=q.where(Devices.ip == ip).get()
    except:
        q=False
    return q

def get_all_device():
    q=Devices.select()
    try:
        q=q
    except:
        q=False
    return q

def get_devices_by_id(ids):
    q=Devices.select().where(Devices.id << ids)
    try:
        q=list(q)
    except Exception as e :
        log.error(e)
        q=False
    return q

def get_devices_by_id2(ids):
    q=Devices.select().where(Devices.id << ids)
    try:
        q=q
    except Exception as e :
        log.error(e)
        q=False
    return q

#same with get all devices but we dont return sensetive data
def get_all_device_api():
    q=Devices.select(
        Devices.id,
        Devices.name ,
        Devices.ip ,
        Devices.mac ,
        Devices.details ,
        Devices.uptime ,
        Devices.license ,
        Devices.interface ,
        Devices.user_name ,
        Devices.port ,
        Devices.update_availble ,
        Devices.current_firmware ,
        Devices.arch ,
        Devices.sensors ,
        Devices.upgrade_availble ,
        Devices.owner ,
        Devices.created ,
        Devices.modified
    ).order_by(Devices.id)

    try:
        q=list(q.dicts())
    except:
        q=False

    return q

def update_devices_firmware_status(data):
    database.execute_sql("SELECT setval('devices_id_seq', MAX(id), true) FROM devices")
    query=Devices.insert_many(data).on_conflict(conflict_target=Devices.id,update={Devices.update_availble:EXCLUDED.update_availble,Devices.upgrade_availble:EXCLUDED.upgrade_availble,Devices.current_firmware:EXCLUDED.current_firmware,Devices.arch:EXCLUDED.arch})
    query.execute() 
    return True

def update_device(devid, user_name, password, ip, peer_ip, name):
    device=get_device(devid)
    if not device:
        return False
    try:
        query=Devices.update(user_name=user_name, password=password, ip=ip, peer_ip=peer_ip, name=name).where(Devices.id == devid)
        query.execute()
    except:
        return False
    return True

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)

