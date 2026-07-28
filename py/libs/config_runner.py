#!/usr/bin/python
# -*- coding: utf-8 -*-

# config_runner.py — Multi-brand automation orchestrator.
# MikroWizard.com , Mikrotik router management solution
#
# Entrypoints:
#   run_device_job(config) — execute one command on one device (16-step contract)
#   run_bulk_job(job_config) — execute on many devices via ThreadPoolExecutor

import os
import re
import json
import hashlib
import uuid
import time
import logging
import socket
import threading
from datetime import datetime, timezone

from concurrent.futures import ThreadPoolExecutor, as_completed

import peewee
from playhouse.shortcuts import model_to_dict as peewee_model_to_dict

from libs.db.db import database
from libs.db.db_device import Devices
from libs.db.db_pam import DeviceTemplates, DeviceConnections
from libs.db.db_user_tasks import Snippets
from libs.db.db_config_versions import ConfigVersions, CommandExecutionLog
from libs.db import db_backups
from libs import util
import config

try:
    from libs.diff_exclusions import compile_exclusions, apply_exclusions
except ImportError:
    def compile_exclusions(canonical):
        return {}

    def apply_exclusions(text, compiled_excl, section=None):
        return text
from libs.device_connector import (
    connect_and_execute,
    build_prompt_re,
    DeviceAuthError,
    DeviceTimeoutError,
    DeviceConnectionError,
    DeviceCommandError,
)
from libs.hook_runner import run_hooks

log = logging.getLogger("config_runner")

VERSIONS_DIR = os.path.join(getattr(config, "BACKUP_DIR", "/opt/mikrowizard/backups"), "versions")
_DEVMODE = os.environ.get("DEV_MODE") == "true"

# ---------------------------------------------------------------------------
# Blob store (content-addressed, atomic writes)


def store_blob(content, kind):
    """Store `content` in {kind}/{h[:2]}/{h[2:4]}/{h}.txt, return rel path.

    kind ∈ {'raw','norm'}.  Atomic: writes to .tmp file then os.replace().
    """
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    rel_path = "{}/{}/{}.txt".format(kind, content_hash[:2], content_hash[2:4], content_hash)
    abs_path = os.path.join(VERSIONS_DIR, rel_path)

    if os.path.exists(abs_path):
        return rel_path

    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    tmp_path = abs_path + ".tmp-{}-{}".format(os.getpid(), threading.get_ident())
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, abs_path)
    return rel_path


def get_blob(storage_path):
    """Read content from a relative storage_path.  Returns str or raises."""
    abs_path = os.path.join(VERSIONS_DIR, storage_path)
    with open(abs_path, "r", encoding="utf-8") as f:
        return f.read()


def get_blob_size(storage_path):
    """Return cached file size or None."""
    abs_path = os.path.join(VERSIONS_DIR, storage_path)
    try:
        return os.path.getsize(abs_path)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Safe model → dict (JSONB fields may be strings)


def _template_to_dict(template):
    if template is None:
        return {}
    data = peewee_model_to_dict(template)
    for key in (
        "connection", "prompt", "privilege_escalation", "commands",
        "pagination", "error_patterns", "post_login_commands",
        "pre_logout_commands", "diff_exclusions", "pre_connect",
        "post_disconnect", "config_mode",
    ):
        val = data.get(key)
        if isinstance(val, str):
            try:
                data[key] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass
        elif val is None:
            data[key] = {} if key in ("diff_exclusions", "commands") else []
    return data


# ---------------------------------------------------------------------------
# Command resolution (including {context_key} substitution)


def resolve_command_string(template, command_key=None, custom_command=None,
                           snippet_content=None, snippet=None, device=None,
                           hook_context=None):
    """Resolve the CLI command string.  Returns (command_string, is_config_mode)."""
    is_config_mode = False
    command = None

    if command_key and template:
        commands_map = template.get("commands") or {}
        command = commands_map.get(command_key)

    if not command and custom_command is not None:
        command = custom_command

    if not command and snippet_content:
        if snippet and getattr(snippet, "template_command_key", None):
            commands_map = template.get("commands") if template else {}
            tmpl_cmd = commands_map.get(snippet.template_command_key) if commands_map else None
            if tmpl_cmd and "{snippet}" in tmpl_cmd:
                command = tmpl_cmd.replace("{snippet}", snippet_content)
            elif tmpl_cmd:
                command = "{} {}".format(tmpl_cmd, snippet_content)
        if not command:
            command = snippet_content
        if snippet and getattr(snippet, "is_config_mode", False):
            is_config_mode = True

    if command and device:
        name = device.peer_ip if getattr(device, "peer_ip", None) else device.ip
        command = command.replace("[mikrowizard]", name)

    if command and hook_context:
        for key, value in hook_context.items():
            if not isinstance(value, str):
                continue
            placeholder = "{" + key + "}"
            if placeholder in command:
                command = command.replace(placeholder, value)

    return command, is_config_mode


# ---------------------------------------------------------------------------
# Single-device executor


def run_device_job(config):
    """16-step execution contract (see plan §2).

    Required config keys:
        device_id, execution_run_id
    Optional:
        template_id, command_key, custom_command, snippet_content, snippet_id,
        capture_output, user_task_id, timeout

    :returns dict per the §2 result-dict contract.
    """
    device_id = config["device_id"]
    execution_run_id = config.get("execution_run_id", str(uuid.uuid4()))
    capture_output = config.get("capture_output", False)
    skip_versioning = config.get("skip_versioning", False)
    session_conn = config.get("session_conn")
    keep_session = config.get("keep_session", False)

    result = {
        "device_id": device_id, "command_key": config.get("command_key"),
        "status": "error", "is_changed": False, "version_num": None,
        "version_id": None, "execution_log_id": None, "duration_ms": 0,
        "error": None, "device_name": "", "device_ip": "",
        "session_conn": None, "session_template": None,
        "session_prompt_re": None, "session_legacy_creds": None,
    }
    if capture_output:
        result["output_raw"] = None
        result["output_normalized"] = None

    try:
        # --- 1. LOAD ---
        device = Devices.get_by_id(device_id)
        result["device_name"] = device.name
        result["device_ip"] = device.ip
        if _DEVMODE:
            log.info("[DEV] device=%s id=%s type=%s template_id=%s",
                     device.name, device_id, getattr(device, "device_type", "?"),
                     getattr(device, "template_id", None))

        template_id = config.get("template_id") or device.template_id
        template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id) if template_id else None
        t_dict = _template_to_dict(template)

        # Fail loudly on missing template when template-driven
        if not template and (config.get("command_key") or
                             (config.get("snippet_id") and not config.get("custom_command"))):
            msg = "Device {} has no template assigned; cannot resolve command".format(device_id)
            result["error"] = msg
            result["execution_log_id"] = _log_execution(
                None, execution_run_id, device_id, None, config.get("command_key"),
                "", 0, None, None, 0, "error", msg, 0, False, None
            )
            return result

        # --- 2. RESOLVE command ---
        snippet = None
        if config.get("snippet_id"):
            snippet = Snippets.get_or_none(Snippets.id == config["snippet_id"])

        command_string, is_config_mode = resolve_command_string(
            t_dict, config.get("command_key"), config.get("custom_command"),
            config.get("snippet_content"), snippet, device, None
        )
        if not command_string:
            raise ValueError("No command resolved")

        result["command_key"] = config.get("command_key")
        if _DEVMODE:
            log.info("[DEV] command=%s key=%s cm=%-5s tpl_id=%s",
                     command_string[:200], result["command_key"], is_config_mode, template_id)

        # --- 3. BUILD API OPTIONS (for hooks) ---
        api_options = None
        has_routeros_hooks = any(
            (t_dict.get("pre_connect") or []) + (t_dict.get("post_disconnect") or [])
        )
        # simpler: check if template has routeros_api hooks
        pre_hooks = t_dict.get("pre_connect") or []
        post_hooks = t_dict.get("post_disconnect") or []
        if any(h.get("type") == "routeros_api" for h in pre_hooks + post_hooks):
            api_options = util.build_api_options(device)

        # --- 4. LEGACY CREDS (for devices without DeviceConnections) ---
        connection = None
        try:
            from libs.db.db_pam import get_device_connection as get_dc
            connection = get_dc(device_id, "ssh") or get_dc(device_id, "telnet")
        except Exception:
            pass
        legacy_creds = (util.decrypt_data(device.user_name) if device.user_name else "",
                        util.decrypt_data(device.password) if device.password else "")

        # --- 5. PRE-HOOKS ---
        hook_context = run_hooks(pre_hooks, "pre_connect", device, t_dict, {
            "api_options": api_options,
        })
        if _DEVMODE and hook_context:
            safe_ctx = {k: v for k, v in hook_context.items() if "password" not in k.lower() and "secret" not in k.lower()}
            log.info("[DEV] pre_hooks context=%s", safe_ctx)

        # Re-resolve command with hook context (for {export_flags} etc.)
        command_string, is_config_mode = resolve_command_string(
            t_dict, config.get("command_key"), config.get("custom_command"),
            config.get("snippet_content"), snippet, device, hook_context
        )

        # --- 6. PROMPT REGEX ---
        prompt_re = build_prompt_re(t_dict)
        if not prompt_re and config.get("command_key"):
            msg = "Template for device {} has no prompt patterns; cannot automate".format(device_id)
            result["error"] = msg
            result["execution_log_id"] = _log_execution(
                config.get("user_task_id"), execution_run_id, device_id, template_id,
                config.get("command_key"), command_string, 0, None, None, 0,
                "error", msg, 0, False, None
            )
            return result

        # --- Session reuse fast-path ---
        if session_conn:
            exec_result = connect_and_execute(
                device_id, command_string, template=template,
                prompt_re=config.get("session_prompt_re"),
                is_config_mode=is_config_mode, timeout=config.get("timeout", 60),
                session_conn=session_conn,
            )
            result["duration_ms"] = exec_result.get("duration_ms", 0)
            if exec_result.get("error"):
                result["error"] = exec_result["error"]
                result["status"] = "error"
                return result
            raw_output = exec_result["output"]
            if capture_output:
                result["output_raw"] = raw_output
            result["status"] = "ok"
            result["session_conn"] = exec_result.get("session_conn")
            return result

        # --- 7. CONNECT + EXECUTE (single attempt; retry handled by caller or wrapper) ---
        exec_result = connect_and_execute(
            device_id, command_string, template=template, hook_context=hook_context,
            legacy_creds=legacy_creds, prompt_re=prompt_re,
            is_config_mode=is_config_mode, timeout=config.get("timeout", 60),
            keep_session=keep_session,
        )
        if _DEVMODE:
            log.info("[DEV] exec result: dur=%sms err=%s err_type=%s output_len=%s",
                     exec_result.get("duration_ms"), exec_result.get("error"),
                     exec_result.get("error_type"), len(exec_result.get("output") or ""))

        result["duration_ms"] = exec_result.get("duration_ms", 0)
        duration_ms = result["duration_ms"]

        if exec_result.get("error"):
            err = exec_result["error"]
            err_type = exec_result.get("error_type", "unknown")
            status = {"auth": "auth_error", "timeout": "timeout"}.get(err_type, "error")
            result["error"] = err
            result["status"] = status
            _log_execution(config.get("user_task_id"), execution_run_id, device_id,
                           template_id, config.get("command_key"), command_string,
                           0, None, None, 0, status, err, duration_ms, False, None)
            run_hooks(post_hooks, "post_disconnect", device, t_dict, hook_context)
            return result

        raw_output = exec_result["output"]
        raw_size = len(raw_output) if raw_output else 0

        if capture_output:
            result["output_raw"] = raw_output

        # --- 8. COMPILE EXCLUSIONS + NORMALIZE ---
        compiled_excl = compile_exclusions(t_dict.get("diff_exclusions"))
        normalized = apply_exclusions(raw_output or "", compiled_excl, config.get("command_key"))

        if capture_output:
            result["output_normalized"] = normalized

        # --- 9. HASH ---
        content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        # --- 10. STORE RAW BLOB (always on success) ---
        raw_path = store_blob(raw_output or "", "raw")
        raw_hash = hashlib.sha256((raw_output or "").encode("utf-8")).hexdigest()

        # --- 11. STORE NORMALIZED BLOB ---
        norm_path = store_blob(normalized, "norm")

        # --- 12. VERSION CHECK (atomic block) ---
        is_versioned = False
        version_id = None
        version_num = 0

        if not skip_versioning:
            now_ = datetime.now(timezone.utc)
            command_key = config.get("command_key") or "show_config"

            try:
                with database.atomic():
                    latest = (ConfigVersions
                              .select()
                              .where(ConfigVersions.device_id == device_id,
                                     ConfigVersions.command_key == command_key)
                              .order_by(ConfigVersions.version_num.desc())
                              .first())

                    if latest and latest.normalized_hash == content_hash:
                        latest.last_seen_at = now_
                        latest.save()
                        is_versioned = False
                        version_id = latest.id
                        version_num = latest.version_num
                    else:
                        version_num = (latest.version_num + 1) if latest else 1
                        new_ver = ConfigVersions.create(
                            device_id=device_id, template_id=template_id,
                            command_key=command_key, version_num=version_num,
                            normalized_hash=content_hash, storage_path=norm_path,
                            size_bytes=len(normalized),
                            previous_version_id=latest.id if latest else None,
                            first_seen_at=now_, last_seen_at=now_,
                        )
                        is_versioned = True
                        version_id = new_ver.id

                    exec_log_id = _log_execution(
                        config.get("user_task_id"), execution_run_id, device_id, template_id,
                        command_key, command_string, raw_size, content_hash, norm_path,
                        raw_hash, "ok", None, duration_ms, is_versioned, version_id, raw_path
                    )

                    # Legacy dual-write (§9)
                    if is_versioned and command_key == "show_config":
                        try:
                            db_backups.create(
                                dev=device,
                                directory=os.path.join(VERSIONS_DIR, raw_path),
                                size=raw_size,
                            )
                        except Exception as e:
                            log.warning("config_runner: legacy Backups dual-write failed: %s", e)

            except peewee.IntegrityError:
                # Concurrent runner won the race — re-read
                time.sleep(0.1)
                latest2 = (ConfigVersions
                           .select()
                           .where(ConfigVersions.device_id == device_id,
                                  ConfigVersions.command_key == command_key)
                           .order_by(ConfigVersions.version_num.desc())
                           .first())
                if latest2 and latest2.normalized_hash == content_hash:
                    is_versioned = False
                    version_id = latest2.id
                    version_num = latest2.version_num
                else:
                    # Retry once
                    version_num = (latest2.version_num + 1) if latest2 else 1
                    new_ver2 = ConfigVersions.create(
                        device_id=device_id, template_id=template_id,
                        command_key=command_key, version_num=version_num,
                        normalized_hash=content_hash, storage_path=norm_path,
                        size_bytes=len(normalized),
                        previous_version_id=latest2.id if latest2 else None,
                        first_seen_at=now_, last_seen_at=now_,
                    )
                    is_versioned = True
                    version_id = new_ver2.id
                exec_log_id = _log_execution(
                    config.get("user_task_id"), execution_run_id, device_id, template_id,
                    command_key, command_string, raw_size, content_hash, norm_path,
                    raw_hash, "ok", None, duration_ms, is_versioned, version_id, raw_path
                )
                if is_versioned and command_key == "show_config":
                    try:
                        db_backups.create(dev=device, directory=os.path.join(VERSIONS_DIR, raw_path), size=raw_size)
                    except Exception:
                        pass
        else:
            command_key = config.get("command_key")
            exec_log_id = _log_execution(
                config.get("user_task_id"), execution_run_id, device_id, template_id,
                command_key, command_string, raw_size, content_hash, norm_path,
                raw_hash, "ok", None, duration_ms, False, None, raw_path
            )

        # --- 13. POST-HOOKS ---
        run_hooks(post_hooks, "post_disconnect", device, t_dict, hook_context)

        result.update({
            "status": "ok", "is_changed": is_versioned, "version_num": version_num,
            "version_id": version_id, "execution_log_id": exec_log_id, "error": None,
            "session_conn": exec_result.get("session_conn"),
            "session_prompt_re": prompt_re,
        })
        return result

    except Exception as e:
        log.exception("run_device_job failed for device %s", device_id)
        result["error"] = str(e)
        if result["execution_log_id"] is None:
            try:
                result["execution_log_id"] = _log_execution(
                    config.get("user_task_id"), execution_run_id, device_id,
                    config.get("template_id") or (device.template_id if "device" in dir() else None),
                    config.get("command_key"), command_string if "command_string" in dir() else "",
                    0, None, None, 0, "error", str(e), result["duration_ms"], False, None
                )
            except Exception:
                pass
        try:
            run_hooks(post_hooks if "post_hooks" in dir() else [], "post_disconnect",
                      device if "device" in dir() else None, t_dict if "t_dict" in dir() else {},
                      hook_context if "hook_context" in dir() else {})
        except Exception:
            pass
        return result


def _log_execution(user_task_id, execution_run_id, device_id, template_id,
                   command_key, command_string, raw_size, normalized_hash,
                   storage_path, raw_hash, status, error_message,
                   duration_ms, is_versioned, version_id, raw_storage_path=None):
    return CommandExecutionLog.create(
        user_task_id=user_task_id, execution_run_id=execution_run_id,
        device_id=device_id, template_id=template_id,
        command_key=command_key, command_string=command_string,
        raw_size_bytes=raw_size, normalized_hash=normalized_hash,
        storage_path=storage_path, raw_hash=raw_hash,
        raw_storage_path=raw_storage_path,
        status=status, error_message=error_message,
        duration_ms=duration_ms, is_versioned=is_versioned,
        version_id=version_id,
        executed_at=datetime.now(timezone.utc),
    ).id


# ---------------------------------------------------------------------------
# Bulk executor


def run_bulk_job(job_config):
    """Execute a command on many devices in parallel.

    job_config keys:
        device_ids: list[int]
        max_workers: int (default 25)
        ... (passed through to run_device_job for each device)
    """
    device_ids = job_config.get("device_ids", [])
    if not device_ids:
        return []

    execution_run_id = str(uuid.uuid4())
    max_workers = min(job_config.get("max_workers", getattr(config, "MAX_CONCURRENT_THREADS", 10)), 50)
    results = []

    def _worker(cfg):
        with database.connection_context():
            return run_device_job(cfg)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for did in device_ids:
            device_config = dict(job_config)
            device_config["device_id"] = did
            device_config["execution_run_id"] = execution_run_id
            futures[executor.submit(_worker, device_config)] = did

        for future in as_completed(futures):
            did = futures[future]
            try:
                res = future.result(timeout=600)
                results.append(res)
            except Exception as e:
                log.exception("Bulk worker for device %s raised", did)
                results.append({
                    "device_id": did, "status": "error",
                    "error": "Thread error: {}".format(e),
                    "is_changed": False, "version_num": None,
                    "duration_ms": 0,
                })

    return sorted(results, key=lambda r: r.get("device_id", 0))
