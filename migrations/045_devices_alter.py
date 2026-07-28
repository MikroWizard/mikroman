# 045_devices_alter.py
# Alters devices to add PAM columns and backfills. Alters snippets.

def migrate(migrator, database, fake=False, **kwargs):
    # devices
    migrator.sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type VARCHAR(50) REFERENCES device_brands(brand)")
    migrator.sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_model VARCHAR(100)")
    migrator.sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS template_id INT REFERENCES device_templates(id)")
    migrator.sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS credential_migrated BOOLEAN NOT NULL DEFAULT FALSE")

    migrator.sql("UPDATE devices SET device_type = 'mikrotik' WHERE device_type IS NULL")
    migrator.sql("UPDATE devices SET device_model = router_type WHERE device_model IS NULL AND router_type IS NOT NULL AND router_type <> ''")
    migrator.sql("""
        UPDATE devices
           SET template_id = (
               SELECT id FROM device_templates
                WHERE brand = 'mikrotik' AND os_type = 'routeros' AND is_system = TRUE LIMIT 1
           )
         WHERE template_id IS NULL AND device_type = 'mikrotik'
    """)

    # snippets
    migrator.sql("ALTER TABLE snippets ADD COLUMN IF NOT EXISTS template_command_key VARCHAR(50)")

def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("ALTER TABLE snippets DROP COLUMN IF EXISTS template_command_key")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS credential_migrated")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS template_id")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS device_model")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS device_type")
