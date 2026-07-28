#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_pam.py: ORM models for PAM (Privileged Access Management) expansion tables.
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com
#
# Tables defined here (all public/core — no pro dependency):
#   device_brands               - vendor/brand lookup (Task 3)
#   device_templates            - connection templates per brand/OS (Task 4)
#   credentials                 - envelope-encrypted credential store (Task 5)
#   device_connections          - per-device connection config (Task 6)

import logging

from libs.db.db import BaseModel, User, database
from libs.db.db_device import Devices
from libs.db.db_groups import DevGroups
from peewee import *
from playhouse.postgres_ext import ArrayField, BinaryJSONField, BooleanField

log = logging.getLogger("db_pam")


# ---------------------------------------------------------------------------
# Task 3 — device_brands


class DeviceBrands(BaseModel):
    """Lookup table of supported device vendors/brands."""

    brand = TextField(primary_key=True)  # e.g. 'mikrotik', 'cisco'
    display_name = TextField()  # e.g. 'MikroTik', 'Cisco'
    is_active = BooleanField(default=True)
    is_system = BooleanField(default=False)  # system brands (seeded by migration) are not user-editable
    created = DateTimeField()

    class Meta:
        db_table = "device_brands"


def get_all_brands(active_only=True):
    """Return all (or only active) device brands."""
    q = DeviceBrands.select()
    if active_only:
        q = q.where(DeviceBrands.is_active == True)
    try:
        return list(q.dicts())
    except Exception as e:
        log.error(e)
        return []


def get_brand(brand):
    """Return a single brand by primary key, or None."""
    try:
        return DeviceBrands.get(DeviceBrands.brand == brand)
    except DeviceBrands.DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# Task 4 — device_templates


class DeviceTemplates(BaseModel):
    """Connection templates per brand/OS combination.

    is_system=True rows are seeded by migration and must not be deleted.
    Custom user templates have is_system=False.
    """

    brand = TextField()  # FK → device_brands.brand
    os_type = TextField()  # e.g. 'routeros', 'ios'
    display_name = TextField()
    connection = BinaryJSONField(null=True)  # default port, timeout, protocols
    prompt = BinaryJSONField(null=True)  # prompt detection patterns
    privilege_escalation = BinaryJSONField(null=True)  # enable/sudo escalation
    commands = BinaryJSONField(null=True)  # logical key → CLI command mapping
    pagination = BinaryJSONField(null=True)  # pagination handling
    error_patterns = BinaryJSONField(null=True)  # patterns that mean error
    post_login_commands = BinaryJSONField(null=True)  # commands sent right after login
    pre_logout_commands = BinaryJSONField(null=True)  # commands sent before disconnect
    is_system = BooleanField(default=False)  # system template, not user-deletable
    is_active = BooleanField(default=True)
    created = DateTimeField()
    diff_exclusions = BinaryJSONField(null=True)
    pre_connect = BinaryJSONField(null=True)
    post_disconnect = BinaryJSONField(null=True)
    config_mode = BinaryJSONField(null=True)

    class Meta:
        db_table = "device_templates"


def get_template(template_id):
    """Return a single template by id, or None."""
    try:
        return DeviceTemplates.get_by_id(template_id)
    except DeviceTemplates.DoesNotExist:
        return None


def get_template_for_brand(brand, os_type=None):
    """Return the system template for a given brand (and optional os_type), or None."""
    try:
        q = DeviceTemplates.select().where(
            DeviceTemplates.brand == brand,
            DeviceTemplates.is_system == True,
            DeviceTemplates.is_active == True,
        )
        if os_type:
            q = q.where(DeviceTemplates.os_type == os_type)
        return q.get()
    except DeviceTemplates.DoesNotExist:
        return None


def get_generic_template():
    """Return the generic fallback template."""
    return get_template_for_brand("generic", "generic")


def list_templates(include_inactive=False):
    """Return all templates as dicts."""
    q = DeviceTemplates.select()
    if not include_inactive:
        q = q.where(DeviceTemplates.is_active == True)
    try:
        return list(q.order_by(DeviceTemplates.brand, DeviceTemplates.os_type).dicts())
    except Exception as e:
        log.error(e)
        return []

# ---------------------------------------------------------------------------
# Task 5 — credentials
#
# Relationship with the existing `vault` pro table:
#   vault       = per-device username/password pairs used by cloner/VPN (pro-only)
#   credentials = Connection Manager PAM store with per-credential envelope encryption
# The two tables coexist and are NOT merged. credentials does NOT replace vault.


class Credentials(BaseModel):
    """Envelope-encrypted credential store for the Connection Manager.

    Each row stores:
      - username in plain text (usernames are not considered secret)
      - encrypted_password encrypted with a per-row DEK
      - dek_encrypted: the DEK itself, encrypted with the server KEK

    To read the password:
      kek = kek_provider.get_kek()
      plaintext = envelope_crypto.full_decrypt(row.encrypted_password,
                                               row.dek_encrypted, kek)

    NEVER return encrypted_password or dek_encrypted in an API response.
    """

    name = TextField()
    credential_type = TextField(default="ssh")  # 'ssh', 'telnet', 'rdp'
    username = TextField(null=True)
    encrypted_password = TextField(null=True)  # Fernet(DEK).encrypt(password)
    dek_encrypted = TextField()  # Fernet(KEK).encrypt(DEK)
    auth_method = TextField(default="password")  # 'password', 'key'
    encrypted_private_key = TextField(null=True)  # Fernet(DEK).encrypt(private_key)
    passphrase_encrypted = TextField(null=True)  # Fernet(DEK).encrypt(passphrase)
    scope = TextField(default="device")  # 'device', 'group'
    device_id = ForeignKeyField(
        db_column="device_id", null=True, model=Devices, to_field="id"
    )
    group_id = ForeignKeyField(
        db_column="group_id", null=True, model=DevGroups, to_field="id"
    )
    owner_id = ForeignKeyField(
        db_column="owner_id", null=True, model=User, to_field="id"
    )
    notes = TextField(null=True)
    created = DateTimeField()
    modified = DateTimeField()

    class Meta:
        db_table = "credentials"


def get_credential(credential_id):
    """Return a single Credentials row by id, or None."""
    try:
        return Credentials.get_by_id(credential_id)
    except Credentials.DoesNotExist:
        return None


def list_credentials_for_device(device_id):
    """Return credentials scoped to a specific device (no secrets)."""
    try:
        return list(
            Credentials.select(
                Credentials.id,
                Credentials.name,
                Credentials.credential_type,
                Credentials.username,
                Credentials.auth_method,
                Credentials.scope,
                Credentials.device_id,
                Credentials.group_id,
                Credentials.notes,
                Credentials.created,
                Credentials.modified,
                # NOTE: encrypted_password, dek_encrypted intentionally excluded
            )
            .where(Credentials.device_id == device_id)
            .dicts()
        )
    except Exception as e:
        log.error(e)
        return []


def list_credentials_for_group(group_id):
    """Return credentials scoped to a device group (no secrets)."""
    try:
        return list(
            Credentials.select(
                Credentials.id,
                Credentials.name,
                Credentials.credential_type,
                Credentials.username,
                Credentials.auth_method,
                Credentials.scope,
                Credentials.device_id,
                Credentials.group_id,
                Credentials.notes,
                Credentials.created,
                Credentials.modified,
            )
            .where(Credentials.group_id == group_id)
            .dicts()
        )
    except Exception as e:
        log.error(e)
        return []


# ---------------------------------------------------------------------------
# Task 6 — device_connections


class DeviceConnections(BaseModel):
    """Stores how to connect to each device on each protocol.

    One row per (device_id, protocol) pair — enforced by UNIQUE constraint.
    `credential_id` is the credential used for initial login.
    `privileged_credential_id` is the separate credential used for enable/sudo
    escalation (may be NULL if the same credential handles both, or if the
    device template has no privilege_escalation defined).
    """

    device_id = ForeignKeyField(
        db_column="device_id", null=False, model=Devices, to_field="id",
        backref="connections", on_delete="CASCADE"
    )
    protocol = TextField()  # 'ssh', 'telnet', 'webfig'
    port = IntegerField(null=True)
    credential_id = ForeignKeyField(
        db_column="credential_id", null=True, model=Credentials, to_field="id"
    )
    privileged_credential_id = ForeignKeyField(
        db_column="privileged_credential_id",
        null=True,
        model=Credentials,
        to_field="id",
    )
    auth_mode = TextField(default="credential")  # 'credential', 'prompt'
    is_default = BooleanField(default=False)
    ssl = BooleanField(default=False)
    agent_modes = BinaryJSONField(null=True)  # Per-device override for agent modes
    connection_type = TextField(default="device")  # 'device', 'override', 'shared', 'user'
    notes = TextField(null=True)
    created = DateTimeField()
    modified = DateTimeField()

    class Meta:
        db_table = "device_connections"


def get_device_connection(device_id, protocol):
    """Return a single DeviceConnections row for a device/protocol pair, or None."""
    try:
        return DeviceConnections.get(
            DeviceConnections.device_id == device_id,
            DeviceConnections.protocol == protocol,
        )
    except DeviceConnections.DoesNotExist:
        return None


def get_device_connection_by_id(conn_id):
    """Return a DeviceConnections row by PK, or None."""
    try:
        return DeviceConnections.get_by_id(conn_id)
    except DeviceConnections.DoesNotExist:
        return None


def list_device_connections(device_id):
    """Return all connection configs for a device as dicts."""
    try:
        return list(
            DeviceConnections.select()
            .where(DeviceConnections.device_id == device_id)
            .order_by(DeviceConnections.protocol)
            .dicts()
        )
    except Exception as e:
        log.error(e)
        return []



