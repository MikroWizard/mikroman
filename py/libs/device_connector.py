#!/usr/bin/python
# -*- coding: utf-8 -*-

# device_connector.py — Netmiko-based device connector with full template-driven
# interaction. ALWAYS uses device_type='generic' / 'generic_telnet'.  Prompt
# detection, privilege escalation, pagination, and error detection all come
# from the device template JSONB fields.
#
# IMPORTANT: this module MUST NOT import libs.util (import cycle).  Legacy
# credential resolution is the caller's responsibility and is passed in via
# the legacy_creds tuple to connect_device().

import re
import time
import logging
import socket
import os

from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.terminal_server.terminal_server import TerminalServerTelnet, TerminalServerSSH
from playhouse.shortcuts import model_to_dict as _peewee_dict

from libs.db.db_pam import DeviceTemplates, DeviceConnections, Credentials, get_template_for_brand
from libs.db.db_device import Devices
from libs import kek_provider, envelope_crypto

log = logging.getLogger("device_connector")
_DEVMODE = os.environ.get("DEV_MODE") == "true"


# ---------------------------------------------------------------------------
# Custom exception hierarchy


class DeviceConnectionError(Exception):
    pass


class DeviceAuthError(DeviceConnectionError):
    pass


class DeviceTimeoutError(DeviceConnectionError):
    pass


class DeviceCommandError(DeviceConnectionError):
    pass


# ---------------------------------------------------------------------------
# Netmiko subclasses that skip auto-login so we control credential exchange
# via the template's prompt patterns (same approach Terminal Gateway uses).
# TerminalServerTelnet/SSH are what netmiko 4.7 maps 'generic_telnet'/'generic' to.


class _NoAutoLogin:
    def core_login(self):
        pass


class TemplateDrivenTelnet(_NoAutoLogin, TerminalServerTelnet):
    pass


class TemplateDrivenSSH(_NoAutoLogin, TerminalServerSSH):
    pass


class TemplateDrivenMikrotikSSH(_NoAutoLogin, TerminalServerSSH):
    """SSH driver for MikroTik RouterOS.

    RouterOS's SSH console requires the login options appended to the username
    (c=no colors, t=disable terminal auto-detection, 511w/4098h=term size) and
    CRLF line endings; otherwise it emits a terminal-init handshake and never
    shows the prompt.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("default_enter", "\r\n")
        super().__init__(*args, **kwargs)

    def _modify_connection_params(self):
        if "+" not in self.username:
            self.username += "+ct511w4098h"
        self.ansi_escape_codes = True


# ---------------------------------------------------------------------------
# Prompt regex builder (MANDATORY — see plan §3.2)
# ...existing code until build_netmiko_params, unchanged...

# Prompt regex builder (MANDATORY — see plan §3.2)


def build_prompt_re(template):
    prompt_config = (template.get("prompt") or {}) if isinstance(template, dict) else {}
    if hasattr(template, "prompt") and template.prompt:
        prompt_config = template.prompt or {}
    patterns = prompt_config.get("patterns") or []
    if not patterns:
        return None
    return "(" + "|".join(patterns) + ")"


# Cross-vendor login failure patterns — applied post-output so we catch
# what generic_telnet / generic miss when the vendor uses nonstandard prompts.
_AUTH_FAIL_PATTERNS = [
    re.compile(r"(?i)%\s*login\s*invalid"),       # Cisco
    re.compile(r"(?i)%\s*bad\s*password"),         # Cisco
    re.compile(r"(?i)%\s*authentication\s*failed"), # Cisco / generic
    re.compile(r"(?i)%\s*access\s*denied"),         # Cisco / generic
    re.compile(r"(?i)login\s*incorrect"),           # Juniper / HP / Linux
    re.compile(r"(?i)permission\s*denied"),          # Linux / generic
    re.compile(r"(?i)authentication\s*failure"),     # Fortinet / generic
    re.compile(r"(?i)invalid\s*(username|password)"), # MikroTik / generic
    re.compile(r"(?i)could\s*(not|n.t)\s*login"),    # MikroTik / generic
    re.compile(r"(?i)wrong\s*(username|password)"),   # Generic
    re.compile(r"(?i)connection\s*closed\s*by"),      # SSH rejection
    re.compile(r"(?i)connection\s*refused"),          # Connection refused
]


def _is_login_failure(output):
    if not output:
        return False
    stripped = output.strip()
    if len(stripped) > 300:
        return False  # unlikely to be just a login failure
    for pat in _AUTH_FAIL_PATTERNS:
        if pat.search(stripped):
            return True
    return False


# ---------------------------------------------------------------------------
# Credential resolution (PAM path only — legacy is the caller's job)


def load_credentials(device_id, connection):
    """Resolve (username, password, enable_password) from connection + vault.

    Only resolves via Credentials table (PAM path).  Returns (None,None,None)
    when no credential rows exist — the caller must provide legacy creds via
    connect_device(..., legacy_creds=(user, pass)).
    """
    username = None
    password = None
    enable_password = None

    if connection and connection.credential_id:
        try:
            cred = Credentials.get_by_id(connection.credential_id)
            username = cred.username
            kek = kek_provider.get_kek()
            if cred.encrypted_password and cred.auth_method != "key":
                password = envelope_crypto.full_decrypt(
                    cred.encrypted_password, cred.dek_encrypted, kek
                )
            elif cred.encrypted_private_key:
                password = envelope_crypto.full_decrypt(
                    cred.encrypted_private_key, cred.dek_encrypted, kek
                )
        except Credentials.DoesNotExist:
            pass
        except Exception as e:
            log.warning("load_credentials: decrypt failed for device %s: %s", device_id, e)

    if connection and connection.privileged_credential_id:
        try:
            priv_cred = Credentials.get_by_id(connection.privileged_credential_id)
            kek = kek_provider.get_kek()
            enable_password = envelope_crypto.full_decrypt(
                priv_cred.encrypted_password, priv_cred.dek_encrypted, kek
            )
        except Credentials.DoesNotExist:
            pass
        except Exception as e:
            log.warning("load_credentials: enable decrypt failed for device %s: %s", device_id, e)

    return username, password, enable_password


# ---------------------------------------------------------------------------
# Connection building


def get_default_connection(device_id, preferred_protocol="ssh"):
    # Always prefer SSH first, regardless of is_default flag
    conn = DeviceConnections.get_or_none(
        DeviceConnections.device_id == device_id,
        DeviceConnections.protocol == preferred_protocol,
    )
    if not conn:
        conn = DeviceConnections.get_or_none(
            DeviceConnections.device_id == device_id, DeviceConnections.is_default == True
        )
    return conn


def build_netmiko_params(device, connection, template, hook_context, legacy_creds):
    protocol = connection.protocol if connection else "ssh"
    device_type = "generic" if protocol == "ssh" else "generic_telnet"

    port = hook_context.get("ssh_port") if hook_context else None
    if not port and connection:
        port = connection.port
    if not port:
        conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
        port = conn_conf.get("default_port_ssh", 22) if protocol == "ssh" else conn_conf.get("default_port_telnet", 23)

    host = device.ip

    pam_user, pam_pass, _ = load_credentials(device.id, connection)
    username = pam_user or ""
    password = pam_pass or ""
    enable_password = None

    if connection and connection.privileged_credential_id:
        _, _, enable_password = load_credentials(device.id, connection)

    if (not username or not password) and legacy_creds:
        username = legacy_creds[0] or username
        password = legacy_creds[1] or password

    if _DEVMODE:
        cred_src = "PAM" if (pam_user or pam_pass) else ("legacy" if legacy_creds and legacy_creds[0] else "none")
        log.info("[DEV] creds: src=%s user=%s user_len=%d pass_len=%d has_enable=%s proto=%s conn_id=%s cred_id=%s",
                 cred_src, username, len(username), len(password), bool(enable_password),
                 protocol, getattr(connection, "id", None) if connection else None,
                 getattr(connection, "credential_id", None) if connection else None)

    conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
    timeout = conn_conf.get("timeout", 30)

    params = {
        "device_type": device_type,
        "host": host,
        "port": int(port),
        "username": username,
        "password": password,
        "timeout": timeout,
        "global_delay_factor": 1,
        "session_log": None,
    }
    if enable_password:
        params["secret"] = enable_password

    if _DEVMODE:
        import tempfile
        log_file = tempfile.NamedTemporaryFile(
            prefix="netmiko_", suffix=".log", mode="w", delete=False, encoding="utf-8"
        )
        params["session_log"] = log_file.name
        log.info("[DEV] session log: %s", log_file.name)

    return params


# ---------------------------------------------------------------------------
# Template-driven login — replaces Netmiko's generic auto-login.
# Uses the template's prompt patterns (login_pattern, password_pattern,
# prompt.patterns) to detect prompts and verify successful login.
# This is the same approach the Terminal Gateway already uses, and it
# avoids Netmiko's hardcoded base_prompt which falsely matches '%' in
# Cisco-style error messages.


def _template_driven_login(conn, template, username, password, timeout=30):
    """Handle login using the template's prompt.login_pattern and
    prompt.password_pattern.

    For SSH: paramiko already authenticated at the transport layer. Skip the
    credential exchange and only verify the prompt is reachable.
    For Telnet: perform the full credential exchange.

    All prompt detection comes from the template — never relies on Netmiko's
    generic base_prompt (which falsely matches '%' on Cisco).
    """
    prompt_config = (template.get("prompt") or {}) if isinstance(template, dict) else {}
    login_pat = prompt_config.get("login_pattern", r"[Uu]sername:?")
    password_pat = prompt_config.get("password_pattern", r"[Pp]assword:?")
    prompt_patterns = prompt_config.get("patterns") or []
    prompt_re = "(" + "|".join(prompt_patterns) + ")" if prompt_patterns else None

    is_ssh = getattr(conn, "protocol", "") == "ssh"

    # --- 1. Read initial banner ---
    output = ""
    try:
        output = conn.read_channel_timing(read_timeout=10)
    except Exception:
        pass
    if _DEVMODE:
        log.info("[DEV] login banner (%d bytes, proto=%s): %s",
                 len(output), "ssh" if is_ssh else "telnet", output[:500])

    # --- 2-3. Credential exchange (Telnet only — SSH already authed) ---
    post_pass = ""
    post_user = ""
    if not is_ssh:
        # --- 2. Detect username prompt from template → send username ---
        if re.search(login_pat, output, re.IGNORECASE):
            try:
                if _DEVMODE:
                    log.info("[DEV] detected login prompt, sending username (len=%d)", len(username))
                conn.write_channel(username + "\r\n")
                post_user = conn.read_channel_timing(read_timeout=10) or ""
                output += post_user
            except Exception as e:
                log.warning("template_login: username send failed: %s", e)
            if _DEVMODE:
                log.info("[DEV] after username (%d bytes): %s", len(post_user), post_user[:300])

        # --- 3. Detect password prompt from template → send password ---
        if re.search(password_pat, output, re.IGNORECASE):
            try:
                if _DEVMODE:
                    log.info("[DEV] detected password prompt, sending password (len=%d)", len(password))
                conn.write_channel(password + "\r\n")
                post_pass = conn.read_channel_timing(read_timeout=10) or ""
                output += post_pass
            except Exception as e:
                log.warning("template_login: password send failed: %s", e)
            if _DEVMODE:
                log.info("[DEV] after password (%d bytes): %s", len(post_pass), post_pass[:300])

    # --- 4. Check for login failure ---
    if _is_login_failure(post_pass or output):
        raise DeviceAuthError("Login failed: {}".format((post_pass or output).strip()[:200]))

    if post_pass and re.search(login_pat, post_pass, re.IGNORECASE):
        raise DeviceAuthError("Login failed: device re-prompting for credentials")

    # --- 5. Verify login by matching template prompt.patterns ---
    if prompt_re:
        for attempt in range(3):
            if attempt > 0:
                try:
                    # Use write_channel — send_command_timing needs base_prompt
                    conn.write_channel("\r\n")
                    extra = conn.read_channel_timing(read_timeout=5) or ""
                    if extra:
                        output += extra
                        # Check ONLY the latest response for failures/re-prompts
                        if _is_login_failure(extra):
                            raise DeviceAuthError("Login failed: {}".format(extra.strip()[:200]))
                        if re.search(login_pat, extra, re.IGNORECASE):
                            raise DeviceAuthError("Login failed: device re-prompting for credentials")
                except DeviceAuthError:
                    raise
                except Exception:
                    pass

            if re.search(prompt_re, output):
                if _DEVMODE:
                    log.info("[DEV] login OK: prompt matched on attempt %d", attempt + 1)
                return

        raise DeviceAuthError(
            "Login failed: no template prompt found. Output: {}".format(output.strip()[:300])
        )

    if _DEVMODE:
        log.info("[DEV] login OK: no prompt patterns to verify")


def connect_device(device_id, template, connection, hook_context=None, legacy_creds=None):
    device = Devices.get_by_id(device_id)
    params = build_netmiko_params(device, connection, template, hook_context, legacy_creds)
    protocol = params["device_type"]
    if protocol == "generic":
        conn_class = (
            TemplateDrivenMikrotikSSH
            if getattr(device, "device_type", "") == "mikrotik"
            else TemplateDrivenSSH
        )
    else:
        conn_class = TemplateDrivenTelnet
    # Keep device_type — BaseConnection.__init__ uses it to determine self.protocol
    # (telnet vs SSH transport layer)
    kwargs = dict(params)

    if _DEVMODE:
        log.info("[DEV] connecting: host=%s port=%s type=%s class=%s timeout=%s",
                 params["host"], params["port"], protocol, conn_class.__name__,
                 params.get("timeout"))

    try:
        conn = conn_class(**kwargs)
    except NetmikoAuthenticationException as e:
        raise DeviceAuthError("Auth failed for {}: {}".format(device.ip, e))
    except NetmikoTimeoutException as e:
        raise DeviceTimeoutError("Timeout connecting to {}:{}/{}: {}".format(
            device.ip, params["port"], protocol, e))
    except socket.error as e:
        raise DeviceConnectionError("Socket error for {}:{}: {}".format(
            device.ip, params["port"], e))

    # Template-driven login — reads banner, detects login/password prompts
    # from template, sends credentials, verifies prompt matches template patterns
    _template_driven_login(
        conn, template,
        params.get("username", ""), params.get("password", ""),
        timeout=params.get("timeout", 30)
    )

    return conn, device


# ---------------------------------------------------------------------------
# Interaction


def execute_privilege_escalation(conn, template, enable_password):
    priv = (template.get("privilege_escalation") or {}) if isinstance(template, dict) else {}
    if not priv or not priv.get("command"):
        return

    cmd = priv["command"]
    # Canonical schema (command/password_prompt/success_pattern) with legacy
    # aliases (prompt_pattern/enable_prompt/prompt) so existing seeded templates
    # keep working. sudo-based escalations always require a password prompt, so
    # infer one when a (legacy) template omits it.
    password_prompt = priv.get("password_prompt") or priv.get("prompt_pattern")
    if not password_prompt and re.search(r"(^|\s)sudo\b", str(cmd)):
        password_prompt = r"[Pp]assword:?"
    success_pattern = priv.get("success_pattern") or priv.get("enable_prompt") or priv.get("prompt")
    needs_pw = bool(password_prompt)

    # Skip if escalation password is required but not provided
    if needs_pw and not enable_password:
        return

    # Send escalation command (keep raw output so password prompts survive the
    # empty-base_prompt driver's strip_prompt)
    output = ""
    try:
        output = conn.send_command_timing(
            cmd, read_timeout=10, strip_prompt=False, strip_command=False
        ) or ""
    except Exception:
        pass

    # If device prompts for escalation password, send it directly
    if password_prompt and enable_password and re.search(password_prompt, output, re.IGNORECASE):
        try:
            conn.write_channel(enable_password + "\r\n")
            post = conn.read_channel_timing(read_timeout=5) or ""
            output += post
        except Exception:
            pass

    # Verify we're in privileged mode by matching the enable prompt. Hard-fail
    # only when a password was expected/supplied (a stuck sudo/enable prompt
    # would otherwise swallow the next command). Non-password escalations keep
    # the soft warning to avoid breaking devices with fuzzy success patterns.
    if success_pattern and not re.search(success_pattern, output):
        if needs_pw and enable_password:
            raise DeviceCommandError(
                "Privilege escalation failed for '{}': {}".format(cmd, output.strip()[:200])
            )
        log.warning("Privilege escalation may have failed. Output: %s", output[:200])


def _send_single_line(conn, command, prompt_re, read_timeout):
    return conn.send_command(command, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)


def _send_multiline_exec(conn, command, prompt_re, read_timeout):
    lines = [l.strip() for l in command.splitlines() if l.strip()]
    if not lines:
        return ""
    output_parts = []
    for line in lines:
        if prompt_re:
            out = conn.send_command(line, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)
        else:
            out = conn.send_command_timing(line, read_timeout=read_timeout)
        output_parts.append(out)
    return "\n".join(output_parts)


def _send_config_mode(conn, command, template, prompt_re, enable_password, read_timeout):
    config_mode = (template.get("config_mode") or {}) if isinstance(template, dict) else {}
    enter_cmd = config_mode.get("enter")
    exit_cmd = config_mode.get("exit")
    save_cmd = config_mode.get("save")

    if not enter_cmd and not exit_cmd:
        raise DeviceCommandError("Template has no config_mode (enter+exit) for config snippet")

    output_parts = []

    if enter_cmd:
        out = conn.send_command(enter_cmd, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)
        output_parts.append(out)

    lines = command.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        out = conn.send_command(line, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)
        output_parts.append(out)

    if exit_cmd:
        out = conn.send_command(exit_cmd, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)
        output_parts.append(out)

    if save_cmd:
        try:
            out = conn.send_command(save_cmd, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)
            output_parts.append(out)
        except Exception as e:
            log.warning("Config-mode save failed: %s", e)

    return "\n".join(output_parts)


def _handle_pagination(conn, template, command, prompt_re, read_timeout):
    pagination = (template.get("pagination") or {}) if isinstance(template, dict) else {}
    if not pagination.get("enabled"):
        return conn.send_command(command, expect_string=prompt_re, read_timeout=read_timeout, cmd_verify=False)

    # post_login_commands in execute_command already sent terminal length 0.
    # Skip the redundant attempt — if pagination is still active, handle it below.
    output = conn.send_command_timing(command, read_timeout=read_timeout)
    more_pattern = pagination.get("pattern", "--More--")
    more_key = pagination.get("key", "space")
    key_map = {"space": " ", "enter": "\n", "q": "q"}
    max_pages = 100
    page_count = 0
    while re.search(more_pattern, output) and page_count < max_pages:
        conn.send_command_timing(key_map.get(more_key, " "), read_timeout=5)
        more_out = conn.read_channel_timing(read_timeout=5)
        if more_out:
            output += more_out
        page_count += 1

    # Strip pagination control lines so diffs don't show false changes
    return _strip_pagination(output, more_pattern)


def _strip_pagination(output, pattern):
    """Remove pagination markers from collected output."""
    if not output or not pattern:
        return output or ""
    lines = output.splitlines(keepends=True)
    kept = []
    for line in lines:
        if not re.search(pattern, line):
            kept.append(line)
    return "".join(kept)


def _scan_errors(output, template):
    if not output or not template:
        return
    err_cfg = template.get("error_patterns") if isinstance(template, dict) else None
    if isinstance(err_cfg, dict):
        patterns = err_cfg.get("patterns") or []
    elif isinstance(err_cfg, (list, tuple)):
        patterns = err_cfg
    else:
        patterns = []
    for pattern in patterns:
        if pattern and re.search(pattern, output, re.IGNORECASE):
            log.warning("Error pattern '%s' matched in output", pattern)


def _resolve_export_flags_ssh(conn, command):
    """Fallback: detect RouterOS version over SSH to resolve {export_flags}.

    Used when the routeros_api pre_connect hook could not run (API unreachable).
    Resolution order: template hook (runtime) -> SSH version detection -> ''.
    """
    flags = ""
    try:
        out = conn.send_command_timing(
            ":put [/system resource get version]",
            read_timeout=10, strip_prompt=False, strip_command=False,
        ) or ""
        m = re.search(r"(\d+)\.\d+", out)
        if m:
            flags = " show-sensitive" if int(m.group(1)) >= 7 else ""
    except Exception:
        flags = ""
    return command.replace("{export_flags}", flags)


def execute_command(conn, command, template, prompt_re, is_config_mode, enable_password, read_timeout):
    """:returns (output, duration_ms)"""
    start = time.time()

    for cmd in (template.get("post_login_commands") or []):
        try:
            conn.send_command_timing(cmd, read_timeout=5)
        except Exception:
            pass

    execute_privilege_escalation(conn, template, enable_password)

    clean_command = (command or "").strip()
    has_newline = "\n" in clean_command
    if has_newline and is_config_mode:
        output = _send_config_mode(conn, clean_command, template, prompt_re, enable_password, read_timeout)
    elif has_newline:
        output = _send_multiline_exec(conn, clean_command, prompt_re, read_timeout)
    else:
        output = _handle_pagination(conn, template, clean_command, prompt_re, read_timeout)

    if _is_login_failure(output):
        raise DeviceAuthError("Login failed: {}".format(output.strip()[:200]))

    _scan_errors(output, template)
    duration_ms = int((time.time() - start) * 1000)
    return output, duration_ms


def disconnect_device(conn, template):
    for cmd in (template.get("pre_logout_commands") or []):
        try:
            conn.send_command_timing(cmd, read_timeout=5)
        except Exception:
            pass
    try:
        conn.disconnect()
    except Exception:
        pass


def connect_and_execute(device_id, command, template_id=None, template=None,
                        hook_context=None, legacy_creds=None,
                        prompt_re=None, is_config_mode=False, enable_password=None,
                        timeout=60, session_conn=None, keep_session=False):
    """Single-attempt connect → execute → disconnect.  Retry is the caller's job.

    If session_conn is provided, reuse it (skip connect/disconnect).
    If keep_session is True, keep connection open and return it for reuse.

    :returns dict(output, duration_ms, error, error_type, session_conn)
    """
    conn_obj = session_conn
    disconnect_at_end = not keep_session and conn_obj is None
    try:
        if not template and template_id:
            template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        if not template and device_id:
            dev_obj = Devices.get_or_none(Devices.id == device_id)
            if dev_obj:
                brand = getattr(dev_obj, "device_type", None) or "mikrotik"
                template = get_template_for_brand(brand)
        if not template:
            template = {}
        if not isinstance(template, dict):
            template = _peewee_dict(template)

        connection = get_default_connection(device_id)

        if not prompt_re:
            prompt_re = build_prompt_re(template)

        if not enable_password and connection and connection.privileged_credential_id:
            _, _, enable_password = load_credentials(device_id, connection)

        if conn_obj is None:
            conn_obj, device = connect_device(device_id, template, connection, hook_context, legacy_creds)
        else:
            device = Devices.get_by_id(device_id)

        # Resolve any remaining {export_flags} over SSH (API hook may have failed).
        if conn_obj is not None and command and "{export_flags}" in command:
            command = _resolve_export_flags_ssh(conn_obj, command)

        output, duration_ms = execute_command(
            conn_obj, command, template, prompt_re, is_config_mode, enable_password, timeout
        )
        if disconnect_at_end:
            disconnect_device(conn_obj, template)
        return {"output": output, "duration_ms": duration_ms, "error": None, "error_type": None, "session_conn": conn_obj}

    except DeviceAuthError as e:
        return {"output": None, "duration_ms": 0, "error": str(e), "error_type": "auth", "session_conn": None}
    except DeviceTimeoutError as e:
        return {"output": None, "duration_ms": 0, "error": str(e), "error_type": "timeout", "session_conn": None}
    except DeviceConnectionError as e:
        return {"output": None, "duration_ms": 0, "error": str(e), "error_type": "connection", "session_conn": None}
    except DeviceCommandError as e:
        output = None
        try:
            if conn_obj:
                output = conn_obj.read_channel_timing(read_timeout=2)
        except Exception:
            pass
        return {"output": output, "duration_ms": 0, "error": str(e), "error_type": "command", "session_conn": None}
    except Exception as e:
        log.exception("Unexpected connect_and_execute error for device %s", device_id)
        return {"output": None, "duration_ms": 0, "error": str(e), "error_type": "unknown", "session_conn": None}
    finally:
        if disconnect_at_end and conn_obj:
            try:
                disconnect_device(conn_obj, template)
            except Exception:
                pass
