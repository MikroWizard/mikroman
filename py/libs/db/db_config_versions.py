#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_config_versions.py: ORM models for config versioning and execution logging.
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com
#
# Tables defined here (all public/core — no pro dependency):
#   config_versions          - per-device versioned config backups
#   command_execution_log    - every command execution attempt (HIGH VOLUME)
#
# Unique constraint on config_versions is enforced by the SQL expression index
# idx_cv_unique(device_id, COALESCE(template_id,0), command_key, version_num)
# because PostgreSQL forbids expressions in table-level UNIQUE constraints.
# Peewee Meta.indexes deliberately does NOT duplicate it (would create a
# redundant plain index that treats NULL template_id rows as distinct).

import logging

from libs.db.db import BaseModel, database
from libs.db.db_device import Devices
from libs.db.db_pam import DeviceTemplates
from libs.db.db_user_tasks import UserTasks
from peewee import *
from playhouse.postgres_ext import BinaryJSONField, BooleanField

log = logging.getLogger("db_config_versions")


# ---------------------------------------------------------------------------
# config_versions — one row per actual content change


class ConfigVersions(BaseModel):
    device_id = ForeignKeyField(Devices, backref="config_versions", on_delete="CASCADE")
    template_id = ForeignKeyField(DeviceTemplates, null=True, on_delete="SET NULL")
    command_key = CharField(max_length=100, default="show_config")
    version_num = IntegerField()
    normalized_hash = CharField(max_length=64)
    storage_path = TextField()
    size_bytes = IntegerField(default=0)
    previous_version_id = ForeignKeyField("self", null=True, on_delete="SET NULL", backref="next_versions")
    first_seen_at = DateTimeField()
    last_seen_at = DateTimeField()

    class Meta:
        db_table = "config_versions"
        indexes = (
            (("device_id", "command_key", "version_num"), False),
            (("normalized_hash",), False),
        )


# ---------------------------------------------------------------------------
# command_execution_log — always written (every attempt, success or failure)


class CommandExecutionLog(BaseModel):
    user_task_id = ForeignKeyField(UserTasks, null=True, on_delete="SET NULL")
    execution_run_id = UUIDField()
    device_id = ForeignKeyField(Devices, on_delete="CASCADE")
    template_id = ForeignKeyField(DeviceTemplates, null=True, on_delete="SET NULL")
    command_key = CharField(max_length=100, null=True)
    command_string = TextField()
    status = CharField(max_length=20, default="ok")
    error_message = TextField(null=True)
    duration_ms = IntegerField(default=0)
    is_versioned = BooleanField(default=False)
    version_id = ForeignKeyField(ConfigVersions, null=True, on_delete="SET NULL")
    normalized_hash = CharField(max_length=64, null=True)
    storage_path = TextField(null=True)
    raw_hash = CharField(max_length=64, null=True)
    raw_storage_path = TextField(null=True)
    raw_size_bytes = IntegerField(default=0)
    executed_at = DateTimeField()

    class Meta:
        db_table = "command_execution_log"
        indexes = (
            (("device_id", "executed_at"), False),
            (("execution_run_id",), False),
            (("user_task_id",), False),
            (("status",), False),
        )


def get_latest_version(device_id, command_key="show_config", template_id=None):
    """Return the latest ConfigVersions row for a device + command, or None."""
    q = (
        ConfigVersions.select()
        .where(
            ConfigVersions.device_id == device_id,
            ConfigVersions.command_key == command_key,
        )
    )
    if template_id:
        q = q.where(ConfigVersions.template_id == template_id)
    return q.order_by(ConfigVersions.version_num.desc()).first()


def list_versions(device_id, command_key=None, page=1, per_page=50):
    """List config versions for a device with pagination. Returns (rows, total)."""
    q = ConfigVersions.select().where(ConfigVersions.device_id == device_id)
    if command_key:
        q = q.where(ConfigVersions.command_key == command_key)
    total = q.count()
    rows = list(q.order_by(ConfigVersions.version_num.desc()).paginate(page, per_page))
    return rows, total


def list_executions(device_id=None, execution_run_id=None, user_task_id=None, page=1, per_page=50):
    """List execution log entries with optional filters. Returns (rows, total)."""
    q = CommandExecutionLog.select()
    if device_id:
        q = q.where(CommandExecutionLog.device_id == device_id)
    if execution_run_id:
        q = q.where(CommandExecutionLog.execution_run_id == execution_run_id)
    if user_task_id:
        q = q.where(CommandExecutionLog.user_task_id == user_task_id)
    total = q.count()
    rows = list(q.order_by(CommandExecutionLog.executed_at.desc()).paginate(page, per_page))
    return rows, total


def get_execution(execution_log_id):
    """Return a single execution log entry by PK, or None."""
    try:
        return CommandExecutionLog.get_by_id(execution_log_id)
    except CommandExecutionLog.DoesNotExist:
        return None
