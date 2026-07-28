# 045_devices_alter.py
# Alters devices to add PAM columns, backfills, migrates credentials,
# and creates default DeviceConnections. Alters snippets.

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return

    # devices — add PAM columns (execute_sql runs immediately so Python below sees them)
    database.execute_sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type VARCHAR(50) REFERENCES device_brands(brand)")
    database.execute_sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_model VARCHAR(100)")
    database.execute_sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS template_id INT REFERENCES device_templates(id)")
    database.execute_sql("ALTER TABLE devices ADD COLUMN IF NOT EXISTS credential_migrated BOOLEAN NOT NULL DEFAULT FALSE")

    database.execute_sql("UPDATE devices SET device_type = 'mikrotik' WHERE device_type IS NULL")
    database.execute_sql("UPDATE devices SET device_model = router_type WHERE device_model IS NULL AND router_type IS NOT NULL AND router_type <> ''")
    database.execute_sql("""
        UPDATE devices
           SET template_id = (
               SELECT id FROM device_templates
                WHERE brand = 'mikrotik' AND os_type = 'routeros' AND is_system = TRUE LIMIT 1
           )
         WHERE template_id IS NULL AND device_type = 'mikrotik'
    """)

    # ------------------------------------------------------------------
    # Credential migration — decrypt legacy creds, envelope-encrypt, store
    # in the new credentials table.  Auto-provisions a KEK in the server
    # config file if one is not yet configured.
    # ------------------------------------------------------------------
    try:
        import sys, traceback
        from cryptography.fernet import Fernet
        from libs import kek_provider, envelope_crypto
        import datetime, config

        kek = kek_provider.get_kek()
        now_val = datetime.datetime.utcnow()

        cursor = database.execute_sql(
            "SELECT id, user_name, password FROM devices "
            "WHERE credential_migrated = FALSE "
            "  AND user_name IS NOT NULL AND user_name != ''"
        )
        rows = cursor.fetchall()

        print(f"[045] Credential migration: {len(rows)} devices to process")
        migrated = 0

        for dev_id, enc_user, enc_pass in rows:
            try:
                username = (Fernet(config.CRYPT_KEY.encode())
                            .decrypt(enc_user.encode()).decode()) if enc_user else ""
                password = (Fernet(config.CRYPT_KEY.encode())
                            .decrypt(enc_pass.encode()).decode()) if enc_pass else ""
            except Exception as dec_err:
                print(f"[045] WARNING: decrypt failed for device {dev_id}: {dec_err}")
                username = ""
                password = ""

            try:
                bundle = envelope_crypto.full_encrypt(password, kek)

                database.execute_sql(
                    "INSERT INTO credentials "
                    "(name, credential_type, username, encrypted_password, dek_encrypted, "
                    "auth_method, scope, device_id, created, modified) "
                    "VALUES (%s, 'webfig', %s, %s, %s, 'password', 'device', %s, %s, %s)",
                    (f"Device {dev_id}", username, bundle["encrypted_payload"],
                     bundle["dek_encrypted"], dev_id, now_val, now_val),
                )

                database.execute_sql(
                    "UPDATE devices SET credential_migrated = TRUE WHERE id = %s",
                    (dev_id,),
                )
                migrated += 1
            except Exception as ins_err:
                print(f"[045] ERROR migrating creds for device {dev_id}: {ins_err}")
                traceback.print_exc(file=sys.stderr)

        print(f"[045] Credential migration complete. Migrated {migrated}/{len(rows)} devices.")

    except ImportError as ie:
        print(f"[045] Credential migration SKIPPED — missing dependency: {ie}")
    except Exception as outer_err:
        print(f"[045] Credential migration FAILED: {outer_err}")
        traceback.print_exc(file=sys.stderr)

    # ------------------------------------------------------------------
    # Default DeviceConnections for existing MikroTik devices (queued via migrator).
    # ------------------------------------------------------------------
    migrator.sql("""
        INSERT INTO device_connections (device_id, protocol, port, credential_id,
                                        auth_mode, is_default, connection_type, created, modified)
        SELECT d.id, 'api',
               COALESCE(NULLIF(d.port, '')::int, 8728),
               c.id,
               'credential', TRUE, 'device', NOW(), NOW()
          FROM devices d
          LEFT JOIN credentials c ON c.device_id = d.id AND c.scope = 'device'
         WHERE d.device_type = 'mikrotik'
           AND NOT EXISTS (SELECT 1 FROM device_connections dc
                            WHERE dc.device_id = d.id AND dc.protocol = 'api')
    """)

    migrator.sql("""
        INSERT INTO device_connections (device_id, protocol, port, credential_id,
                                        auth_mode, is_default, connection_type, created, modified)
        SELECT d.id, 'ssh',
               22,
               c.id,
               'credential', FALSE, 'device', NOW(), NOW()
          FROM devices d
          LEFT JOIN credentials c ON c.device_id = d.id AND c.scope = 'device'
         WHERE d.device_type = 'mikrotik'
           AND NOT EXISTS (SELECT 1 FROM device_connections dc
                            WHERE dc.device_id = d.id AND dc.protocol = 'ssh')
    """)

    # snippets
    migrator.sql("ALTER TABLE snippets ADD COLUMN IF NOT EXISTS template_command_key VARCHAR(50)")


def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("DELETE FROM device_connections WHERE protocol IN ('api','ssh') AND device_id IN (SELECT id FROM devices WHERE device_type = 'mikrotik')")
    migrator.sql("DELETE FROM credentials WHERE scope = 'device' AND credential_type = 'webfig'")
    migrator.sql("UPDATE devices SET credential_migrated = FALSE WHERE credential_migrated = TRUE")
    migrator.sql("ALTER TABLE snippets DROP COLUMN IF EXISTS template_command_key")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS credential_migrated")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS template_id")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS device_model")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS device_type")
