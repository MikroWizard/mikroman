# 047_bigint_logs.py
# Alters high-volume tables to use BIGINT primary keys with matching sequences.
# Prevents INT32 overflow on deployments with many devices and heavy log volumes.

from peewee import *
import logging

log = logging.getLogger('peewee_migrate')

TABLES = [
    'events',      # device alerts/events
    'auth',        # authentication logs
    'syslogs',     # syslog events (highest volume)
    'user_tasks',  # task execution history
]

def migrate(migrator, database, fake=False, **kwargs):
    for table in TABLES:
        try:
            database.execute_sql(f'ALTER TABLE {table} ALTER COLUMN id TYPE BIGINT;')
            database.execute_sql(f'ALTER SEQUENCE IF EXISTS {table}_id_seq AS BIGINT;')
            log.info(f"Upgraded {table}.id to BIGINT")
        except Exception as e:
            log.warning(f"Could not upgrade {table}.id (may not exist or already BIGINT): {e}")

def rollback(migrator, database, fake=False, **kwargs):
    for table in TABLES:
        try:
            database.execute_sql(f'ALTER TABLE {table} ALTER COLUMN id TYPE INT;')
            database.execute_sql(f'ALTER SEQUENCE IF EXISTS {table}_id_seq AS INT;')
        except Exception:
            pass
