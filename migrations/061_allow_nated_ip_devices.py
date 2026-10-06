# 061_allow_nated_ip_devices.py
# 1. Drops the single-column unique index on devices(ip) (idx_devices_ip_unique)
#    which blocked multiple devices from sharing a NATed WAN IP.
# 2. Backfills devices.port from device_connections for existing devices.
# 3. Creates a composite partial unique index on (ip, port) so multiple distinct
#    devices (different device names, credentials, OS types) can share the same NATed IP
#    as long as their external/service ports differ. Genuine duplicates (same IP & same Port)
#    remain strictly prevented.

import logging

log = logging.getLogger("migration_061")


def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return

    # 1. Drop old single-IP unique index
    migrator.sql("DROP INDEX IF EXISTS idx_devices_ip_unique")

    # 2. Backfill devices.port from device_connections for existing devices where port is empty
    migrator.sql("""
        UPDATE devices d
        SET port = CAST(dc.port AS text)
        FROM device_connections dc
        WHERE dc.device_id = d.id
          AND dc.is_default = TRUE
          AND (d.port IS NULL OR d.port = '' OR d.port = '0');
    """)

    # 3. For MikroTik devices where port is still empty, default to 8728 (or 8729 if SSL)
    migrator.sql("""
        UPDATE devices
        SET port = CASE WHEN ssl = TRUE THEN '8729' ELSE '8728' END
        WHERE (port IS NULL OR port = '' OR port = '0')
          AND (device_type = 'mikrotik' OR device_type IS NULL);
    """)

    # 4. For any other remaining devices where port is empty, default to '22'
    migrator.sql("""
        UPDATE devices
        SET port = '22'
        WHERE (port IS NULL OR port = '' OR port = '0');
    """)

    # 5. Create composite partial unique index on (ip, port)
    migrator.sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_port_unique
            ON devices (ip, port)
            WHERE ip IS NOT NULL AND ip <> '' AND port IS NOT NULL AND port <> '';
    """)


def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("DROP INDEX IF EXISTS idx_devices_ip_port_unique")
    migrator.sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_unique
            ON devices (ip)
            WHERE ip IS NOT NULL AND ip <> '';
    """)
