# 046_password_encryption_migration.py
# Migrates credential data from the old `devices` table columns to the new `credentials` table
# using envelope encryption.

import datetime
import logging

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
        
    try:
        from libs.db.db_device import Devices
        from libs.db.db_pam import Credentials
        from libs import util
        from libs import kek_provider
        from libs import envelope_crypto
    except ImportError as e:
        logging.error(f"Failed to import modules for data migration: {e}")
        return

    # Check/Load KEK
    try:
        kek = kek_provider.get_kek()
    except Exception as e:
        logging.error(f"Failed to load KEK: {e}")
        raise e

    devices_to_migrate = Devices.select().where(
        Devices.credential_migrated == False,
        Devices.user_name.is_null(False),
        Devices.user_name != ''
    )

    success_count = 0
    error_count = 0

    for dev in devices_to_migrate:
        try:
            username = util.decrypt_data(dev.user_name) if dev.user_name else ""
            
            password = ""
            if dev.password:
                try:
                    password = util.decrypt_data(dev.password)
                except Exception as e:
                    logging.warning(f"Could not decrypt password for device {dev.id}. Leaving password empty. Err: {e}")
            
            encrypted_bundle = envelope_crypto.full_encrypt(password, kek)
            
            now = datetime.datetime.utcnow()
            Credentials.create(
                name=f"Device {dev.id} Migrated Credential",
                credential_type="ssh" if getattr(dev, 'device_type', 'mikrotik') != "mikrotik" else "webfig",
                username=username,
                encrypted_password=encrypted_bundle['encrypted_payload'],
                dek_encrypted=encrypted_bundle['dek_encrypted'],
                auth_method="password",
                scope="device",
                device_id=dev.id,
                owner_id=dev.owner, 
                created=now,
                modified=now
            )

            dev.credential_migrated = True
            dev.save()
            
            success_count += 1
        except Exception as e:
            logging.error(f"Error migrating device {dev.id}: {e}")
            error_count += 1

    logging.info(f"Credential Data Migration completed. Success: {success_count}, Errors: {error_count}")

def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    try:
        from libs.db.db_device import Devices
        from libs.db.db_pam import Credentials
    except ImportError:
        return
    
    migrator.sql("UPDATE devices SET credential_migrated = false")
    migrator.sql("DELETE FROM credentials WHERE name LIKE 'Device % Migrated Credential'")
