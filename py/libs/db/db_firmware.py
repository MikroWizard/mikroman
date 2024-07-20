#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_firmware.py: Models and functions for accsessing db related to Firmware
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

from libs.db.db import BaseModel,get_object_or_none
import logging
log = logging.getLogger("db_firmware")


class Firmware(BaseModel):
    version = TextField()
    location = TextField()
    architecture = TextField()
    sha256 = TextField()
    created = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'firmware'

def get_firm(id):
    return get_object_or_none(Firmware, id=id)

def get_frim_by_version(version,arch):
    return get_object_or_none(Firmware, version=version, architecture=arch)

def create_perm(datas):
    for data in datas:
        perm=Firmware()
        perm.version = data["version"]
        perm.location = data["location"]
        perm.architecture = data["architecture"]
        perm.sha256 = data["sha256"]
        perm.save(force_insert=True)

def query_firms(page=0, limit=1000, search=None):
    page = int(page or 0)
    limit = int(limit or 1000)
    q = Firmware.select()
    if search:
        search = "%"+search+"%"
        q = q.where(Firmware.version ** search)
    q = q.paginate(page, limit).order_by(Firmware.id.desc())
    return q

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)


