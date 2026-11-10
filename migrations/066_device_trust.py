# 066_device_trust.py
# Optional router identity verification (libs/device_trust.py): the trusted API-SSL
# certificate fingerprint and SSH host key of each device (trust on first use).
# Nothing is verified until an admin selects a 'pin' / 'ca' mode in Settings.

import logging

log = logging.getLogger("migration_066")


def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.device_trust (
            device_id        INTEGER PRIMARY KEY REFERENCES public.devices(id) ON DELETE CASCADE,
            tls_fingerprint  TEXT NULL,
            tls_seen_at      TIMESTAMP WITH TIME ZONE NULL,
            ssh_host_key     TEXT NULL,
            ssh_seen_at      TIMESTAMP WITH TIME ZONE NULL
        )
    """)
    for key in ("device_tls_verify", "device_ssh_verify"):
        migrator.sql(
            "INSERT INTO public.sysconfig (key, value, created, modified) VALUES ('{}', 'off', NOW(), NOW()) "
            "ON CONFLICT (key) DO NOTHING".format(key))
    migrator.sql(
        "INSERT INTO public.sysconfig (key, value, created, modified) VALUES ('device_tls_cafile', '', NOW(), NOW()) "
        "ON CONFLICT (key) DO NOTHING")
    log.info("Migration 066: device_trust table and settings ready")


def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("DROP TABLE IF EXISTS public.device_trust")
    migrator.sql("DELETE FROM public.sysconfig WHERE key IN ('device_tls_verify', 'device_ssh_verify', 'device_tls_cafile')")
