#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_permissions.py: Models and functions for accsessing db related to device permisions
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from peewee import *

import config
from libs.db.db import BaseModel,get_object_or_none

import logging
log = logging.getLogger("db_permisions")


class Perms(BaseModel):
    name = TextField()
    perms = TextField()
    created = DateTimeField()
    modified = DateTimeField()
    class Meta:
        # `indexes` is a tuple of 2-tuples, where the 2-tuples are
        # a tuple of column names to index and a boolean indicating
        # whether the index is unique or not.
        db_table = 'permissions'

def get_perm(id):
    return get_object_or_none(Perms, id=id)

def create_perm(name,perms):
    perm=Perms()
    perm.name = name
    perm.perms = perms
    perm.save(force_insert=True)

def delete_perm(id):
    if id in [1,2,3]:
        return False
    perm = get_object_or_none(Perms, id=id)
    perm.delete_instance(recursive=True)

def get_perm_by_name(name):
    if not name:
        return None

    try:
        # case insensitive query
        if config.IS_SQLITE:
            sql = "SELECT * FROM permissions where name = ? LIMIT 1"
            args = name.lower()
        else:
            sql = "SELECT * FROM permissions where LOWER(name) = LOWER(%s) LIMIT 1"
            args = (name,)
        return list(Perms.raw(sql, args))[0]

    except IndexError:
        return None
    
def query_perms(page=0, limit=1000, search=None):
    page = int(page or 0)
    limit = int(limit or 1000)

    q = Perms.select()
    q = q.paginate(page, limit).order_by(Perms.id.desc())
    return q

# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)

