# 054_devices_partial_unique.py
# 1. Drops the blanket UNIQUE constraint on devices.mac and replaces it with
#    a partial unique index for non-empty MACs (MikroTik devices).
#    Non-MikroTik devices with empty MACs no longer violate uniqueness.
# 2. Adds a UNIQUE index on devices.ip to prevent duplicate IPs across all
#    device types. IP is the natural unique key for non-MikroTik devices.
#    Application code already validates this (api_dev.py:230,
#    api_non_mikrotik_pro.py:90) — this is belt-and-suspenders at the DB level.

def migrate(migrator, database, fake=False, **kwargs):
    # --- MAC: drop blanket unique, add partial for non-empty only ---
    migrator.sql("ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_mac_key")
    migrator.sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_nonempty
            ON devices (mac) WHERE mac IS NOT NULL AND mac <> ''
    """)

    # --- IP: unique across ALL device types ---
    migrator.sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_unique
            ON devices (ip) WHERE ip IS NOT NULL AND ip <> ''
    """)

def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("DROP INDEX IF EXISTS idx_devices_ip_unique")
    migrator.sql("DROP INDEX IF EXISTS idx_devices_mac_nonempty")
    migrator.sql("ALTER TABLE devices ADD CONSTRAINT devices_mac_key UNIQUE (mac)")
