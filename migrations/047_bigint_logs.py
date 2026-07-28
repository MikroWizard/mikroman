# 047_bigint_logs.py
# Alters free log tables to use BIGINT for their primary key sequences.

from peewee import *
import logging

log = logging.getLogger('peewee_migrate')

def migrate(migrator, database, fake=False, **kwargs):
    tables_to_upgrade = [
        'events',
        'auth',
        'radacct'
    ]
    
    for table in tables_to_upgrade:
        try:
            with database.atomic():
                database.execute_sql(f'ALTER TABLE {table} ALTER COLUMN id TYPE BIGINT;')
            log.info(f"Successfully altered {table}.id to BIGINT")
        except Exception as e:
            log.warning(f"Could not alter {table}.id to BIGINT (maybe it doesn't exist or is already BIGINT?): {e}")

def rollback(migrator, database, fake=False, **kwargs):
    tables_to_upgrade = [
        'events',
        'auth',
        'radacct'
    ]
    for table in tables_to_upgrade:
        try:
            with database.atomic():
                database.execute_sql(f'ALTER TABLE {table} ALTER COLUMN id TYPE INT;')
        except Exception:
            pass
