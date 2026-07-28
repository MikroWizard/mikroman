# 050_connection_manager_perm.py
# Adds "connection_manager" to the permissions system for all users and groups.
#
# Architecture note (critical):
#   session['perms'] = json.loads(users.adminperms)   <- set at login by account.build_session()
#   The `permissions` table holds NAMED PROFILES used when creating/editing users.
#   The actual per-user permissions live in users.adminperms as a JSON blob.
#   Both must be updated — patching only `permissions` leaves all existing users unchanged.
#
# Mapping rule: connection_manager level mirrors the existing device permission level.
#   device:full  -> connection_manager:full
#   device:write -> connection_manager:write
#   device:read  -> connection_manager:read
#   device:none / missing -> not updated (admin can grant manually)
#
# Idempotent: WHERE NOT (... ? 'connection_manager') guards prevent double-application.
# Public migration -- no pro dependency.

def migrate(migrator, database, fake=False, **kwargs):
    # 1. Update named permission profiles (used as templates when creating new users)
    migrator.sql("""
        UPDATE permissions
           SET perms = (
                   perms::jsonb || jsonb_build_object(
                       'connection_manager',
                       CASE perms::jsonb->>'device'
                           WHEN 'full'  THEN 'full'
                           WHEN 'write' THEN 'write'
                           WHEN 'read'  THEN 'read'
                           ELSE 'none'
                       END
                   )
               )::text
         WHERE perms IS NOT NULL
           AND perms::jsonb ? 'device'
           AND NOT (perms::jsonb ? 'connection_manager')
    """)

    # 2. Update individual user permissions stored in users.adminperms
    migrator.sql("""
        UPDATE users
           SET adminperms = (
                   adminperms::jsonb || jsonb_build_object(
                       'connection_manager',
                       CASE adminperms::jsonb->>'device'
                           WHEN 'full'  THEN 'full'
                           WHEN 'write' THEN 'write'
                           WHEN 'read'  THEN 'read'
                           ELSE 'none'
                       END
                   )
               )::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'device'
           AND NOT (adminperms::jsonb ? 'connection_manager')
    """)


def rollback(migrator, database, fake=False, **kwargs):
    # Remove connection_manager key from permission profiles
    migrator.sql("""
        UPDATE permissions
           SET perms = (perms::jsonb - 'connection_manager')::text
         WHERE perms IS NOT NULL
           AND perms::jsonb ? 'connection_manager'
    """)

    # Remove connection_manager key from individual users
    migrator.sql("""
        UPDATE users
           SET adminperms = (adminperms::jsonb - 'connection_manager')::text
         WHERE adminperms IS NOT NULL
           AND adminperms != ''
           AND adminperms::jsonb ? 'connection_manager'
    """)
