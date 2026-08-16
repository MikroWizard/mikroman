# 057_permissions_taxonomy.py
# Permission taxonomy redesign.
#
# 1. Rename connection_manager -> pam_session + pam_config (for installs that ran 050).
# 2. Merge device_manager -> device (for any install that set it).
# 3. Backfill new categorized permission keys by mirroring a parent permission's level.
# 4. Ensure the protected system admin is never locked out.
#
# Non-destructive: existing adminperms values are NEVER overwritten.
# Every new key is added only when absent (guarded by `NOT (adminperms::jsonb ? '<key>')`),
# and its level mirrors a parent key so existing users keep their effective access.
#
# Public migration -- no pro dependency.

SYSTEM_ADMIN_ID = "37cc36e0-afec-4545-9219-94655805868b"

# (new_key, parent_key) — the new key inherits the parent's level when missing.
NEW_PERMS = [
    ("pam_session", "device"),
    ("pam_config", "device"),
    ("policy", "device"),
    ("vault", "device"),
    ("wireguard", "device"),
    ("sequence", "snippet"),
    ("cloner", "task"),
    ("device_log", "device"),
    ("system_log", "settings"),
    ("customer", "users"),
    ("customer_ticket", "users"),
    ("customer_chat", "users"),
    ("alerts", "settings"),
]

_MIRROR_SQL = """
    UPDATE users
       SET adminperms = (
               adminperms::jsonb || jsonb_build_object(
                   '%(new)s',
                   CASE adminperms::jsonb->>'%(parent)s'
                       WHEN 'full'  THEN 'full'
                       WHEN 'write' THEN 'write'
                       WHEN 'read'  THEN 'read'
                       ELSE 'none'
                   END
               )
           )::text
     WHERE adminperms IS NOT NULL
       AND adminperms != ''
       AND adminperms::jsonb ? '%(parent)s'
       AND NOT (adminperms::jsonb ? '%(new)s')
"""

_SYSADMIN_FILL_SQL = """
    UPDATE users
       SET adminperms = (
               COALESCE(NULLIF(adminperms, ''), '{}')::jsonb
               || jsonb_build_object('%(new)s', 'full')
           )::text
     WHERE id = '%(sysid)s'
       AND NOT (COALESCE(NULLIF(adminperms, ''), '{}')::jsonb ? '%(new)s')
"""


def migrate(migrator, database, fake=False, **kwargs):
    # 1. Rename connection_manager -> pam_session + pam_config (guarded, non-destructive)
    migrator.sql("""
        UPDATE users
           SET adminperms = (
                   adminperms::jsonb
                   || jsonb_build_object('pam_session', adminperms::jsonb->>'connection_manager')
               )::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'connection_manager'
           AND NOT (adminperms::jsonb ? 'pam_session')
    """)
    migrator.sql("""
        UPDATE users
           SET adminperms = (
                   adminperms::jsonb
                   || jsonb_build_object('pam_config', adminperms::jsonb->>'connection_manager')
               )::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'connection_manager'
           AND NOT (adminperms::jsonb ? 'pam_config')
    """)
    migrator.sql("""
        UPDATE users
           SET adminperms = (adminperms::jsonb - 'connection_manager')::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'connection_manager'
    """)

    # 2. Merge device_manager -> device (only when device is absent), then drop it
    migrator.sql("""
        UPDATE users
           SET adminperms = (
                   adminperms::jsonb
                   || jsonb_build_object('device', adminperms::jsonb->>'device_manager')
               )::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'device_manager'
           AND NOT (adminperms::jsonb ? 'device')
    """)
    migrator.sql("""
        UPDATE users
           SET adminperms = (adminperms::jsonb - 'device_manager')::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'device_manager'
    """)

    # 3. Backfill new categorized keys by mirroring their parent
    for new_key, parent_key in NEW_PERMS:
        migrator.sql(_MIRROR_SQL % {"new": new_key, "parent": parent_key})

    # 4. Protected system admin: fill any still-missing new keys with full
    for new_key, parent_key in NEW_PERMS:
        migrator.sql(_SYSADMIN_FILL_SQL % {"new": new_key, "sysid": SYSTEM_ADMIN_ID})


def rollback(migrator, database, fake=False, **kwargs):
    # Remove the new categorized keys
    for new_key, parent_key in NEW_PERMS:
        migrator.sql("""
            UPDATE users
               SET adminperms = (adminperms::jsonb - '%(new)s')::text
             WHERE adminperms IS NOT NULL
               AND adminperms != ''
               AND adminperms::jsonb ? '%(new)s'
        """ % {"new": new_key})

    # Best-effort restore of connection_manager from pam_session
    migrator.sql("""
        UPDATE users
           SET adminperms = (
                   adminperms::jsonb
                   || jsonb_build_object('connection_manager', adminperms::jsonb->>'pam_session')
               )::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'pam_session'
           AND NOT (adminperms::jsonb ? 'connection_manager')
    """)
