# 059_template_protocol.py
# Adds dedicated protocol column to device_templates table for first-class protocol filtering.

import logging

log = logging.getLogger("migration_059")

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return

    migrator.sql("""
        ALTER TABLE device_templates 
        ADD COLUMN IF NOT EXISTS protocol VARCHAR(20) DEFAULT 'ssh' NOT NULL;
    """)

    migrator.sql("""
        UPDATE device_templates
        SET protocol = 'rdp'
        WHERE (connection::jsonb)->>'protocol' = 'rdp'
           OR (connection::jsonb->'protocols') ? 'rdp';

        UPDATE device_templates
        SET protocol = 'vnc'
        WHERE (connection::jsonb)->>'protocol' = 'vnc'
           OR (connection::jsonb->'protocols') ? 'vnc';

        UPDATE device_templates
        SET protocol = 'telnet'
        WHERE ((connection::jsonb)->>'protocol' = 'telnet'
           OR (connection::jsonb->'protocols') = '["telnet"]'::jsonb)
           AND protocol != 'rdp' AND protocol != 'vnc';

        UPDATE device_templates
        SET protocol = 'ssh'
        WHERE protocol IS NULL OR protocol NOT IN ('rdp', 'vnc', 'telnet');

        CREATE INDEX IF NOT EXISTS idx_device_templates_protocol 
        ON device_templates (protocol);
    """)

    log.info("Migration 059 applied: device_templates protocol column added, backfilled, and indexed.")

def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("DROP INDEX IF EXISTS idx_device_templates_protocol;")
    migrator.sql("ALTER TABLE device_templates DROP COLUMN IF EXISTS protocol;")
