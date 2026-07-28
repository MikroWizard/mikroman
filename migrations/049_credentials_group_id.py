# 049_credentials_group_id.py
import logging

log = logging.getLogger("migration_049")

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS group_id INT REFERENCES device_groups(id) ON DELETE SET NULL")
    migrator.sql("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS is_shared BOOLEAN NOT NULL DEFAULT false")

def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("ALTER TABLE credentials DROP COLUMN IF EXISTS group_id")
    migrator.sql("ALTER TABLE credentials DROP COLUMN IF EXISTS is_shared")
