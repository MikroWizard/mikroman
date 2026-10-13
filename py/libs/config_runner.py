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

import peewee
from playhouse.shortcuts import model_to_dict as peewee_model_to_dict

from libs.db.db import database
from libs.db.db_device import Devices
from libs.db.db_pam import DeviceTemplates, DeviceConnections, get_template_for_brand
from libs.db.db_user_tasks import Snippets
from libs.db.db_config_versions import CommandExecutionLog, ConfigVersions
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

try:
    from libs.config_runner_pro import normalize_output, run_versioning
except ImportError:
    def normalize_output(raw_output, t_dict, command_key):
        return raw_output or ""

    def run_versioning(config, execution_run_id, device_id, template_id, device,
                       command_string, raw_size, normalized, content_hash,
                       raw_path, raw_hash, norm_path, duration_ms, skip_versioning):
        command_key = config.get("command_key")
        should_store_backup = (not skip_versioning and command_key == "show_config") or bool(config.get("store_in_backup", False))
        if should_store_backup:
            try:
                db_backups.create(
                    dev=device,
                    directory=os.path.join(VERSIONS_DIR, raw_path),
                    size=raw_size,
                )
            except Exception as e:
                log.warning("config_runner: Backups create failed: %s", e)
        exec_log_id = _log_execution(
            config.get("user_task_id"), execution_run_id, device_id, template_id,
            command_key, command_string, raw_size, content_hash, norm_path,
            raw_hash, "ok", None, duration_ms, False, None, raw_path
        )
        return False, None, 0, exec_log_id

log = logging.getLogger("config_runner")

from libs.device_connector import (
    connect_and_execute,
    build_prompt_re,
    get_cli_connection,
    resolve_session,
    disconnect_device,
    DeviceAuthError,
    DeviceTimeoutError,
    DeviceConnectionError,
    DeviceCommandError,
)
from libs.hook_runner import run_hooks
from libs import job_control

VERSIONS_DIR = os.path.join(getattr(config, "BACKUP_DIR", "/opt/mikrowizard/backups"), "versions")
_DEVMODE = os.environ.get("DEV_MODE") == "true"

try:
    os.makedirs(VERSIONS_DIR, exist_ok=True)
except Exception:
    pass

# ---------------------------------------------------------------------------
# Blob store (content-addressed, atomic writes)


# RouterOS export header: '# 2026-10-11 20:09:48 by RouterOS 7.17' (v6: '# oct/11/2026 ...').
# It changes on every run, so a raw blob keyed by the full content never deduplicates.
_RAW_VOLATILE_HEAD = re.compile(r"^#[^\n]*?\bby RouterOS\b(?P<ver>[^\n]*)$")
_RAW_KEY_NS = "mw-raw-v1\n"


def raw_dedup_key(raw):
    """Text a raw blob is addressed by: the raw output without the date of the RouterOS export
    header (first 3 lines only; the RouterOS version stays part of the key). An unchanged
    configuration then reuses the first stored raw file, whose header shows when that
    configuration was first seen. Output without such a line is addressed by its full
    content, exactly as before; the stripped form is namespaced, so it never equals the key
    of any other output (e.g. the same text without a header, or an empty output)."""
    if not raw or "by RouterOS" not in raw[:400]:
        return raw or ""
    head = raw.split("\n", 3)
    for idx, line in enumerate(head[:3]):
        m = _RAW_VOLATILE_HEAD.match(line.rstrip("\r"))
        if m:
            rest = head[:idx] + head[idx + 1:]
            return _RAW_KEY_NS + "RouterOS" + m.group("ver") + "\n" + "\n".join(rest)
    return raw


def store_blob(content, kind, key=None):
    """Store `content` in {kind}/{h[:2]}/{h[2:4]}/{h}.txt, return rel path. h = sha256 of
    `key` (default: the content itself; raw blobs use raw_dedup_key).

    kind ∈ {'raw','norm'}.  Atomic: writes to .tmp file then os.replace().
    A reused blob gets a fresh mtime: retention never removes a blob a running job is about
    to reference (libs/retention.py only deletes blobs older than its grace period).
    """
    content_hash = hashlib.sha256((content if key is None else key).encode("utf-8")).hexdigest()
    rel_path = "{}/{}/{}/{}.txt".format(kind, content_hash[:2], content_hash[2:4], content_hash)
    abs_path = os.path.join(VERSIONS_DIR, rel_path)

    if os.path.exists(abs_path):
        try:
            os.utime(abs_path, None)
            if os.path.exists(abs_path):
                return rel_path
        except OSError:
            pass        # mtime not refreshed: write it again below (fresh mtime, same address)

    try:
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    except OSError as e:
        log.error("Cannot create backup directory %s: %s", os.path.dirname(abs_path), e)
        raise
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
            data[key] = {} if key in ("diff_exclusions", "commands", "error_patterns", "prompt", "connection", "pagination", "privilege_escalation", "config_mode") else []
    return data


# ---------------------------------------------------------------------------
# Command resolution (including {context_key} substitution)


def resolve_command_string(template, command_key=None, custom_command=None,
                           snippet_content=None, snippet=None, device=None,
                           hook_context=None, server_ip=None):
    """Resolve the CLI command string.  Returns (command_string, is_config_mode).

    server_ip: value of [mikrowizard]; looked up from the device when not given."""
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

    if command and "[mikrowizard]" in command and (server_ip is not None or device):
        if server_ip is None:
            server_ip = util.resolve_peer_ip(device)
        command = command.replace("[mikrowizard]", server_ip or "")

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

    kept_conn = None            # session kept open for the caller (keep_session)
    try:
        # --- 1. LOAD (scoped DB checkout) ---
        with database.connection_context():
            device = Devices.get_by_id(device_id)
            result["device_name"] = device.name
            result["device_ip"] = device.ip
            if _DEVMODE:
                log.info("[DEV] device=%s id=%s type=%s template_id=%s",
                         device.name, device_id, getattr(device, "device_type", "?"),
                         getattr(device, "template_id", None))

            template_id = config.get("template_id") or getattr(device, "template_id", None)
            template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id) if template_id else None
            if not template:
                brand = getattr(device, "device_type", None) or "mikrotik"
                template = get_template_for_brand(brand)
                if template:
                    template_id = template.id
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
                config.get("snippet_content"), snippet, None, None
            )
            server_ip = None
            if command_string and "[mikrowizard]" in command_string:
                server_ip = util.resolve_peer_ip(device) or ""
                command_string = command_string.replace("[mikrowizard]", server_ip)
            if not command_string:
                raise ValueError("No command resolved")

            result["command_key"] = config.get("command_key")
            if _DEVMODE:
                log.info("[DEV] command=%s key=%s cm=%-5s tpl_id=%s",
                         command_string[:200], result["command_key"], is_config_mode, template_id)

            # --- 3. BUILD API OPTIONS (for hooks) ---
            api_options = None
            pre_hooks = t_dict.get("pre_connect") or []
            post_hooks = t_dict.get("post_disconnect") or []
            if any(h.get("type") == "routeros_api" for h in pre_hooks + post_hooks):
                api_options = util.build_api_options(device)

            # --- 4. CLI SESSION DATA (connection row + credentials, resolved now: no DB
            # connection may be held while the router is being talked to) ---
            legacy_creds = _legacy_creds(device)
            session = resolve_session(device, get_cli_connection(device_id), legacy_creds)

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
            config.get("snippet_content"), snippet, None, hook_context, server_ip=server_ip
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

        # --- 7. CONNECT + EXECUTE (single attempt; retry handled by caller or wrapper) ---
        job_timeout = config.get("timeout") or (t_dict.get("connection") or {}).get("timeout") or 120
        exec_result = connect_and_execute(
            device_id, command_string, template=t_dict, hook_context=hook_context,
            legacy_creds=legacy_creds, prompt_re=config.get("session_prompt_re") or prompt_re,
            is_config_mode=is_config_mode, timeout=job_timeout,
            session_conn=session_conn, keep_session=keep_session or bool(session_conn),
            session=session, exact_prompt=(config.get("command_key") == "show_config"),
        )
        if _DEVMODE:
            log.info("[DEV] exec result: dur=%sms err=%s err_type=%s output_len=%s",
                     exec_result.get("duration_ms"), exec_result.get("error"),
                     exec_result.get("error_type"), len(exec_result.get("output") or ""))

        if keep_session and not session_conn:
            kept_conn = exec_result.get("session_conn")
        result["duration_ms"] = exec_result.get("duration_ms", 0)
        duration_ms = result["duration_ms"]

        if exec_result.get("error"):
            err = exec_result["error"]
            err_type = exec_result.get("error_type", "unknown")
            status = {"auth": "auth_error", "timeout": "timeout"}.get(err_type, "error")
            result["error"] = err
            result["status"] = status
            with database.connection_context():
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
        normalized = normalize_output(raw_output or "", t_dict, config.get("command_key"))

        if capture_output:
            result["output_normalized"] = normalized

        # --- 9. HASH ---
        content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        # --- 10. STORE RAW BLOB (always on success) ---
        raw_path = store_blob(raw_output or "", "raw", key=raw_dedup_key(raw_output or ""))
        raw_hash = hashlib.sha256((raw_output or "").encode("utf-8")).hexdigest()

        # --- 11. STORE NORMALIZED BLOB ---
        norm_path = store_blob(normalized, "norm")

        # --- 12. VERSION CHECK (atomic block with scoped DB context) ---
        with database.connection_context():
            is_versioned, version_id, version_num, exec_log_id = run_versioning(
                config, execution_run_id, device_id, template_id, device,
                command_string, raw_size, normalized, content_hash,
                raw_path, raw_hash, norm_path, duration_ms, skip_versioning,
            )

        # --- 13. POST-HOOKS ---
        # A kept session (sequence) is still open: its post hooks (e.g. disable SSH again)
        # run when the session is closed (close_kept_session).
        kept = exec_result.get("session_conn") if (keep_session and not session_conn) else None
        if not session_conn and kept is None:
            run_hooks(post_hooks, "post_disconnect", device, t_dict, hook_context)

        result.update({
            "status": "ok", "is_changed": is_versioned, "version_num": version_num,
            "version_id": version_id, "execution_log_id": exec_log_id, "error": None,
            "session_conn": exec_result.get("session_conn") or session_conn,
            "session_prompt_re": config.get("session_prompt_re") or prompt_re,
        })
        if kept is not None:
            result["session_template"] = t_dict
            result["session_post"] = (post_hooks, device, hook_context)
        return result

    except Exception as e:
        log.exception("run_device_job failed for device %s", device_id)
        result["error"] = str(e)
        result["session_conn"] = None
        # a session kept open for the caller (sequence) is useless now: close it
        if kept_conn is not None:
            try:
                disconnect_device(kept_conn, t_dict if "t_dict" in dir() else {})
            except Exception:
                pass
        if result["execution_log_id"] is None:
            try:
                with database.connection_context():
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


def close_kept_session(result):
    """Close the session a keep_session=True run_device_job returned and run the template's
    post_disconnect hooks it postponed. Safe to call with any result."""
    if not result:
        return
    conn = result.get("session_conn")
    tmpl = result.get("session_template") or {}
    if conn is not None:
        try:
            disconnect_device(conn, tmpl)
        except Exception:
            pass
    post = result.get("session_post")
    if post:
        hooks, device, hook_context = post
        try:
            run_hooks(hooks, "post_disconnect", device, tmpl, hook_context)
        except Exception as e:
            log.warning("post_disconnect hooks after kept session failed: %s", e)
    result["session_conn"] = None
    result["session_post"] = None


def _legacy_creds(device):
    """Device user/password. For MikroTik devices empty values fall back to the system
    default user/password, exactly like the RouterOS API side (util.build_api_options) -
    those defaults are RouterOS credentials and are never offered to other brands."""
    user = util.decrypt_data(device.user_name) if device.user_name else ""
    password = util.decrypt_data(device.password) if device.password else ""
    brand = (getattr(device, "device_type", None) or "mikrotik").lower()
    if brand == "mikrotik" and (not user or not password):
        try:
            default_user, default_pass = util.get_default_user_pass()
        except Exception:
            default_user, default_pass = "", ""
        user = user or default_user
        password = password or default_pass
    return (user or "", password or "")


def _log_execution(user_task_id, execution_run_id, device_id, template_id,
                   command_key, command_string, raw_size, normalized_hash,
                   storage_path, raw_hash, status, error_message,
                   duration_ms, is_versioned, version_id, raw_storage_path=None):
    with database.connection_context():
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
        execution_run_id: run id shown to the user (status / stop); generated when missing
        max_workers: int (default: job_control.job_concurrency(len(device_ids)))
        deadline: seconds after which no new device starts (0 = none)
        should_cancel: optional callable -> bool; checked before each device starts
        ... (passed through to run_device_job for each device)

    Every device gets exactly one result; devices that did not run say why
    ('cancelled', 'deadline', 'busy').
    """
    device_ids = list(job_config.get("device_ids", []) or [])
    if not device_ids:
        return []

    execution_run_id = job_config.get("execution_run_id") or str(uuid.uuid4())
    max_workers = job_config.get("max_workers") or job_control.job_concurrency(len(device_ids))
    should_cancel = job_config.get("should_cancel")
    base = {k: v for k, v in job_config.items()
            if k not in ("should_cancel", "device_ids", "max_workers", "deadline")}

    def _worker(did):
        cfg = dict(base)
        cfg["device_id"] = did
        cfg["execution_run_id"] = execution_run_id
        return run_device_job(cfg)

    def _skipped(did, reason, message):
        return {
            "device_id": did, "status": reason if reason in ("cancelled", "busy", "deadline") else "error",
            "error": message, "is_changed": False, "version_num": None, "duration_ms": 0,
        }

    results = job_control.run_devices(
        device_ids, _worker, concurrency=max_workers, deadline=job_config.get("deadline") or 0,
        should_cancel=should_cancel, skipped=_skipped)
    return sorted(results, key=lambda r: r.get("device_id", 0))
