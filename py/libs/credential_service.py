#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import logging
from libs.db.db_pam import Credentials
try:
    from libs.db.db_pam_pro import CredentialRotationHistory
    ISPRO = True
except ImportError:
    ISPRO = False
from libs.db.db_groups import DevGroupRel
from libs import kek_provider
from libs import envelope_crypto
from playhouse.shortcuts import model_to_dict

log = logging.getLogger("credential_service")

class CredentialService:
    @staticmethod
    def _model_to_safe_dict(cred):
        if not cred:
            return None
        d = model_to_dict(cred)
        # CRITICAL: Never expose encrypted blobs in API layer
        d.pop('encrypted_password', None)
        d.pop('dek_encrypted', None)
        d.pop('encrypted_private_key', None)
        d.pop('passphrase_encrypted', None)
        return d

    @staticmethod
    def _resolve_user_credential(device_id, protocol, user_id):
        from libs.db.db_device import Devices
        dev = Devices.get_or_none(Devices.id == device_id)
        if not dev or not user_id or getattr(dev, 'device_type', 'mikrotik') != 'mikrotik':
            return None
        try:
            from libs.db.db_pro import UserPoro
            from libs import utilpro
            up = UserPoro.get_or_none(UserPoro.id == user_id)
            if up:
                # Generate temp password + store temp_hash
                password = utilpro.generate_password(12)
                nthash = utilpro.nt_password_hash(password)
                up.temp_hash = nthash
                up.save()
                return {
                    'method': 'credential',
                    'username': up.username,
                    'password': password,
                    'auth_method': 'password'
                }
        except ImportError:
            pass
        return None

    @staticmethod
    def get_credential_for_connection(device_id, protocol, user_id=None) -> dict:
        """
        Resolves credentials for a device/protocol combination.
        Resolution order (with connection_type support):
          0. If connection_type='user' AND MikroTik → resolve via UserPoro temp_hash
          1. If connection_type='override' → use DeviceConnections.credential_id directly
          2. If connection_type='shared' → use shared/group-scoped credential
          3. DeviceConnections mapping (specific to protocol)
          4. Device-scoped credential matching protocol
          5. Device-scoped credential matching 'webfig' (fallback)
          6. Group-scoped credential matching protocol
          7. Group-scoped credential matching 'webfig' (fallback)
        """
        try:
            kek = kek_provider.get_kek()
        except Exception as e:
            log.error(f"Failed to get KEK: {e}")
            return {'method': 'prompt'}

        from libs.db.db_pam import DeviceConnections
        conn = DeviceConnections.get_or_none(
            DeviceConnections.device_id == device_id,
            DeviceConnections.protocol == protocol
        )
        conn_type = getattr(conn, 'connection_type', 'device') if conn else 'device'

        cred = None

        # 0. User-based creds (MikroTik temp_hash flow)
        if conn_type == 'user':
            user_res = CredentialService._resolve_user_credential(device_id, protocol, user_id)
            if user_res:
                return user_res
            return {'method': 'prompt'}

        # 1. Override cred (explicit credential_id from mapping)
        if conn_type == 'override' and conn and conn.credential_id:
            cred = Credentials.get_or_none(Credentials.id == conn.credential_id)

        # 2. Shared credential (group-scoped, is_shared=True)
        if not cred and conn_type == 'shared':
            group_ids = [rel.group_id.id for rel in DevGroupRel.select().where(DevGroupRel.device_id == device_id)]
            if group_ids:
                cred = Credentials.select().where(
                    Credentials.credential_group_id.in_(group_ids),
                    Credentials.is_shared == True,
                    Credentials.credential_type == protocol
                ).order_by(Credentials.id.desc()).first()

        # 3. DeviceConnections mapping (standard device cred)
        if not cred and conn_type == 'device' and conn and conn.credential_id:
            cred = Credentials.get_or_none(Credentials.id == conn.credential_id)

        # 4. Device-scoped matching protocol
        if not cred:
            cred = Credentials.select().where(
                Credentials.device_id == device_id,
                Credentials.credential_type == protocol,
                Credentials.scope == 'device'
            ).order_by(Credentials.id.desc()).first()

        # 5. Fallback to webfig for ssh/telnet (migrated MikroTik)
        if not cred and protocol in ('ssh', 'telnet'):
            cred = Credentials.select().where(
                Credentials.device_id == device_id,
                Credentials.credential_type == 'webfig',
                Credentials.scope == 'device'
            ).order_by(Credentials.id.desc()).first()

        # 5b. Fallback to any device-scoped credential (handles protocol mismatch)
        if not cred:
            cred = Credentials.select().where(
                Credentials.device_id == device_id,
                Credentials.scope == 'device'
            ).order_by(Credentials.id.desc()).first()

        # 6. Group-scoped matching protocol
        if not cred:
            group_ids = [rel.group_id.id for rel in DevGroupRel.select().where(DevGroupRel.device_id == device_id)]
            if group_ids:
                cred = Credentials.select().where(
                    Credentials.group_id.in_(group_ids),
                    Credentials.credential_type == protocol,
                    Credentials.scope == 'group'
                ).order_by(Credentials.id.desc()).first()

                # 7. Group-scoped fallback
                if not cred and protocol in ('ssh', 'telnet'):
                    cred = Credentials.select().where(
                        Credentials.group_id.in_(group_ids),
                        Credentials.credential_type == 'webfig',
                        Credentials.scope == 'group'
                    ).order_by(Credentials.id.desc()).first()

        if not cred:
            return {'method': 'prompt'}

        # Decrypt
        try:
            password = None
            if cred.encrypted_password:
                password = envelope_crypto.full_decrypt(cred.encrypted_password, cred.dek_encrypted, kek)
            
            result = {
                'method': 'credential',
                'username': cred.username,
                'password': password,
                'auth_method': cred.auth_method
            }
            if cred.auth_method == 'key' and cred.encrypted_private_key:
                try:
                    result['ssh_key'] = envelope_crypto.full_decrypt(
                        cred.encrypted_private_key, cred.dek_encrypted, kek
                    )
                    if cred.passphrase_encrypted:
                        result['ssh_key_passphrase'] = envelope_crypto.full_decrypt(
                            cred.passphrase_encrypted, cred.dek_encrypted, kek
                        )
                except Exception as key_err:
                    log.error(f"Failed to decrypt private key for credential {cred.id}: {key_err}")
            return result
        except Exception as e:
            log.error(f"Failed to decrypt credential {cred.id}: {e}")
            return {'method': 'prompt'}

    @staticmethod
    def create_credential(name, credential_type, username, plaintext_password, scope, 
                          device_id=None, group_id=None, owner_id=None, auth_method='password',
                          is_shared=False, credential_group_id=None) -> int:
        """Encrypts with envelope scheme, inserts into credentials table"""
        kek = kek_provider.get_kek()
        enc_bundle = envelope_crypto.full_encrypt(plaintext_password, kek)

        now = datetime.datetime.utcnow()
        cred = Credentials.create(
            name=name,
            credential_type=credential_type,
            username=username,
            encrypted_password=enc_bundle['encrypted_payload'],
            dek_encrypted=enc_bundle['dek_encrypted'],
            auth_method=auth_method,
            scope=scope,
            device_id=device_id,
            group_id=group_id,
            owner_id=owner_id,
            is_shared=is_shared,
            credential_group_id=credential_group_id,
            created=now,
            modified=now
        )
        return cred.id

    @staticmethod
    def rotate_credential(credential_id, new_password, user_id=None) -> bool:
        """Re-encrypt with new DEK, log to credential_rotation_history"""
        cred = Credentials.get_or_none(Credentials.id == credential_id)
        if not cred:
            return False

        try:
            kek = kek_provider.get_kek()
            enc_bundle = envelope_crypto.full_encrypt(new_password, kek)
            
            cred.encrypted_password = enc_bundle['encrypted_payload']
            cred.dek_encrypted = enc_bundle['dek_encrypted']
            cred.modified = datetime.datetime.utcnow()
            cred.save()

            # Audit log
            now = datetime.datetime.utcnow()
            affected_device_ids = None
            log_device_id = None
            
            if cred.scope == 'device':
                log_device_id = getattr(cred.device_id, 'id', None)
            elif cred.scope == 'group' and cred.group_id:
                rels = DevGroupRel.select().where(DevGroupRel.group_id == cred.group_id)
                affected_device_ids = [r.device_id.id for r in rels]

            if ISPRO:
                CredentialRotationHistory.create(
                credential_id=cred.id,
                device_id=log_device_id,
                affected_device_ids=affected_device_ids,
                rotated_by=user_id,
                rotation_type='manual',
                status='success',
                created=now
            )
            return True
        except Exception as e:
            log.error(f"Rotation failed for credential {credential_id}: {e}")
            return False

    @staticmethod
    def delete_credential(credential_id) -> bool:
        cred = Credentials.get_or_none(Credentials.id == credential_id)
        if not cred:
            return False
        cred.delete_instance()
        return True

    @staticmethod
    def list_credentials(scope=None, device_id=None, group_id=None) -> list:
        """NEVER returns decrypted passwords in the list"""
        q = Credentials.select()
        if scope:
            q = q.where(Credentials.scope == scope)
        if device_id:
            q = q.where(Credentials.device_id == device_id)
        if group_id:
            q = q.where(Credentials.group_id == group_id)
            
        return [CredentialService._model_to_safe_dict(c) for c in q]
