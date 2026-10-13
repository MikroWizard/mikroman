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

import json
import re
import time
import logging
import socket
import os
import tempfile

import paramiko

import config
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.exceptions import ReadTimeout
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
    # Sanitize legacy/unsafe MikroTik patterns (e.g. r"\] ?>", r"\] ?#")
    # that lack line anchors and falsely match script expressions like "[:find ...] >= 0"
    safe_patterns = []
    for pat in patterns:
        if pat in (r"\] ?>", r"\] ?#", r"\]\s*>", r"\]\s*#", r"\]>", r"\]#"):
            safe_patterns.append(r"\[[^\]\r\n]+@[^\]\r\n]+\][^\r\n]*?[>#]\s*$")
        else:
            safe_patterns.append(pat)
    seen = set()
    deduped = []
    for p in safe_patterns:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return "(" + "|".join(deduped) + ")"


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


def get_cli_connection(device_id):
    """The CLI connection row of a device: ssh, else telnet. An 'api' / 'webfig' row (MikroTik
    devices get one as default) is never a CLI target."""
    for proto in ("ssh", "telnet"):
        conn = DeviceConnections.get_or_none(
            DeviceConnections.device_id == device_id, DeviceConnections.protocol == proto)
        if conn:
            return conn
    return None


class DeviceSession(object):
    """Everything needed to open a CLI session, resolved in one short DB block by the caller
    (resolve_session) so that no DB connection is held while talking to the router."""

    __slots__ = ("device_id", "ip", "name", "brand", "protocol", "port", "username", "password",
                 "enable_password", "cred_source", "firmware")

    def __init__(self, device_id, ip, name="", brand="mikrotik", protocol="ssh", port=None, username="",
                 password="", enable_password=None, cred_source="none", firmware=None):
        self.device_id = device_id
        self.ip = ip
        self.name = name
        self.brand = brand or "mikrotik"
        self.protocol = protocol or "ssh"
        self.port = port
        self.username = username or ""
        self.password = password or ""
        self.enable_password = enable_password
        self.cred_source = cred_source
        self.firmware = firmware

    # connect_device() used to return the Devices row; callers only read these
    @property
    def id(self):
        return self.device_id


def resolve_session(device, connection=None, legacy_creds=None):
    """DB part of a CLI session (call inside database.connection_context()).

    Credentials: PAM credential of the ssh/telnet connection row, else the legacy pair
    (device user/password, or the system default user/password - resolved by the caller)."""
    if connection is None:
        connection = get_cli_connection(device.id)
    username, password, enable_password = load_credentials(device.id, connection)
    source = "PAM" if (username or password) else "none"
    username = username or ""
    password = password or ""
    if (not username or not password) and legacy_creds:
        username = legacy_creds[0] or username
        password = legacy_creds[1] or password
        if legacy_creds[0]:
            source = "legacy"
    protocol = connection.protocol if connection and connection.protocol in ("ssh", "telnet") else "ssh"
    return DeviceSession(
        device_id=device.id, ip=device.ip, name=getattr(device, "name", "") or "",
        brand=getattr(device, "device_type", None) or "mikrotik", protocol=protocol,
        port=(connection.port if connection else None), username=username, password=password,
        enable_password=enable_password, cred_source=source,
        firmware=getattr(device, "current_firmware", None))


def build_netmiko_params(device, connection, template, hook_context, legacy_creds, session=None):
    if session is None:
        session = resolve_session(device, connection, legacy_creds)
    protocol = session.protocol
    device_type = "generic" if protocol == "ssh" else "generic_telnet"

    port = hook_context.get("ssh_port") if (hook_context and protocol == "ssh") else None
    if not port:
        port = session.port
    if not port:
        conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
        port = conn_conf.get("default_port_ssh", 22) if protocol == "ssh" else conn_conf.get("default_port_telnet", 23)

    username = session.username
    password = session.password
    enable_password = session.enable_password

    if _DEVMODE:
        log.info("[DEV] creds: src=%s user=%s user_len=%d pass_len=%d has_enable=%s proto=%s",
                 session.cred_source, username, len(username), len(password), bool(enable_password), protocol)

    conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
    timeout = conn_conf.get("timeout", 30)

    params = {
        "device_type": device_type,
        "host": session.ip,
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


SETTLE = 0.3               # seconds of silence that confirm a matched prompt is really the end


_LEADING_FLAGS = re.compile(r"^\(\?[aiLmsux]+\)")


def _end_re(pattern, flags=0, line_start=False):
    """Compiled pattern that only matches at the end of the received data (optionally also
    only at the start of a line). A leading inline flag group such as '(?i)' is kept at the
    front. None when the pattern cannot be used (callers then use the quiet-period read)."""
    if not pattern:
        return None
    lead_flags = ""
    m = _LEADING_FLAGS.match(pattern)
    if m:
        lead_flags, pattern = m.group(0), pattern[m.end():]
    lead = "(?:^|\n)" if line_start else ""
    body = _prompt_part(pattern) if line_start else _noncapturing(pattern)
    try:
        return re.compile("{}{}(?:{})[ \t]*$".format(lead_flags, lead, body), flags)
    except re.error as e:
        log.warning("template pattern %r not usable for prompt detection: %s", pattern, e)
        return None


UNMATCHED_QUIET = 2.0      # data arrived, nothing matched, then this long silence: give up waiting


def _wait_for(conn, patterns, timeout, settle=SETTLE, unmatched_quiet=UNMATCHED_QUIET, slow=None,
              slow_settle=2.0):
    """Read until the received data ends with one of `patterns` (compiled, None ignored) and
    then stays silent for `settle` seconds - prompt-driven, no fixed quiet-period wait.
    Returns (text, matched). Returns early with matched False when data arrived but none of
    the patterns matched and the device then stayed silent for `unmatched_quiet` seconds
    (unexpected prompt - the old quiet-period behaviour), or at `timeout`."""
    patterns = [p for p in patterns if p is not None]
    slow = [p for p in (slow or []) if p is not None]
    patterns += slow
    out = ""
    end = time.time() + timeout
    last_data = None
    while time.time() < end:
        new = conn.read_channel()
        if new:
            out += new
            last_data = time.time()
            continue
        if out and last_data is not None and unmatched_quiet and time.time() - last_data >= unmatched_quiet \
                and not any(p.search(out) for p in patterns):
            return out, False
        if patterns and any(p.search(out) for p in patterns):
            fast_hit = any(p.search(out) for p in patterns if p not in slow)
            time.sleep(settle if fast_hit else slow_settle)
            more = conn.read_channel()
            if not more:
                return out, True
            out += more
            continue
        time.sleep(0.02)
    return out, False


# RouterOS screens that can come between the banner and the prompt (as netmiko's MikroTik
# driver handles them): software license question, 'press Enter' (unlicensed), default
# configuration notice, forced password change (e.g. admin with an empty password).
_MT_SCREENS = [
    (re.compile(r"software license.*\[y/n\]:?[ \t]*$", re.I | re.S), "n", "software license question (answered 'n')"),
    (re.compile(r"new password>[ \t]*$", re.I), "\x03", "password change request (skipped with Ctrl-C)"),
    (re.compile(r'press "?enter"? to continue!?[ \t]*$', re.I), "\r\n", "'press Enter' notice"),
    # the notice continues after this line ("If you are connected using the above IP ...")
    (re.compile(r"any other key to continue", re.I), "\r\n", "default configuration notice (kept)"),
]


def _is_mikrotik_session(conn, template):
    if isinstance(conn, TemplateDrivenMikrotikSSH):
        return True
    brand = template.get("brand") if isinstance(template, dict) else None
    return (brand or "").lower() == "mikrotik"


def _mikrotik_login_screens(conn, output, prompt_end, timeout=10):
    """Answer RouterOS pre-prompt screens until the prompt shows. Returns the output.
    Only output not yet answered is looked at, so one screen is never answered twice."""
    seen = 0
    for _ in range(6):
        if prompt_end is not None and prompt_end.search(output):
            return output
        fresh = output[seen:][-2000:]
        hit = next(((rx, key, what) for rx, key, what in _MT_SCREENS if rx.search(fresh)), None)
        if hit is None:
            return output
        rx, key, what = hit
        log.warning("RouterOS login: %s", what)
        seen = len(output)
        conn.write_channel(key)
        more, _ = _wait_for(conn, ([prompt_end] if prompt_end is not None else []) +
                            [r for r, _, _ in _MT_SCREENS], timeout)
        output += more
    return output


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
    # a template may store null (e.g. 'Telnet - Enable - No Username'): use the defaults
    login_pat = prompt_config.get("login_pattern") or r"[Uu]sername:?"
    password_pat = prompt_config.get("password_pattern") or r"[Pp]assword:?"
    prompt_patterns = prompt_config.get("patterns") or []
    prompt_re = "(" + "|".join(prompt_patterns) + ")" if prompt_patterns else None

    is_ssh = getattr(conn, "protocol", "") == "ssh"
    prompt_end = _end_re(prompt_re, line_start=True) if prompt_re else None
    login_end = _end_re(login_pat, re.IGNORECASE)
    pass_end = _end_re(password_pat, re.IGNORECASE)

    # --- 1. Read initial banner: until the prompt (or a login / password prompt) ---
    output = ""
    try:
        if prompt_end is not None and is_ssh:
            screens = [r for r, _, _ in _MT_SCREENS] if _is_mikrotik_session(conn, template) else []
            output, _ = _wait_for(conn, [prompt_end, login_end, pass_end] + screens, min(timeout or 10, 10))
        elif prompt_end is not None:
            # telnet: a banner line can look like a prompt ('#####' vs '\S+#') - a prompt
            # only counts after 2 s of silence, the login / password prompts at once
            output, _ = _wait_for(conn, [login_end, pass_end], min(timeout or 10, 10), slow=[prompt_end])
        else:
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
                post_user, _ = _wait_for(conn, [pass_end, prompt_end, login_end], 10)
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
                post_pass, _ = _wait_for(conn, [prompt_end, login_end, pass_end], 10)
                output += post_pass
            except Exception as e:
                log.warning("template_login: password send failed: %s", e)
            if _DEVMODE:
                log.info("[DEV] after password (%d bytes): %s", len(post_pass), post_pass[:300])

    # RouterOS screens before the prompt (license, password change, notices)
    if _is_mikrotik_session(conn, template):
        answered = _mikrotik_login_screens(conn, output, prompt_end)
        if len(answered) > len(output):
            if post_pass:
                post_pass += answered[len(output):]
            output = answered

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
                    extra, _ = _wait_for(conn, [prompt_end, login_end, pass_end], 5)
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
                try:
                    conn.set_base_prompt()
                except Exception:
                    pass
                return

        # the end of the output tells why (the start is only the banner)
        raise DeviceAuthError(
            "Login failed: no template prompt found. Last output: {!r}".format(output.strip()[-300:])
        )

    if _DEVMODE:
        log.info("[DEV] login OK: no prompt patterns to verify")


def connect_device(device_id, template, connection, hook_context=None, legacy_creds=None, session=None):
    """Open and log in a CLI session. With `session` (resolve_session) no DB access happens.
    A session whose login fails is closed before the error is raised."""
    if session is None:
        device = Devices.get_by_id(device_id)
        session = resolve_session(device, connection or get_cli_connection(device_id), legacy_creds)
    params = build_netmiko_params(None, None, template, hook_context, legacy_creds, session=session)
    protocol = params["device_type"]
    brand = session.brand or (template.get("brand") if isinstance(template, dict) else getattr(template, "brand", None)) or "mikrotik"
    if protocol == "generic":
        conn_class = (
            TemplateDrivenMikrotikSSH
            if brand == "mikrotik"
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
        raise DeviceAuthError("Auth failed for {}: {}".format(session.ip, e))
    except NetmikoTimeoutException as e:
        raise DeviceTimeoutError("Timeout connecting to {}:{}/{}: {}".format(
            session.ip, params["port"], protocol, e))
    except (socket.error, EOFError, paramiko.SSHException) as e:
        raise DeviceConnectionError("Connection error for {}:{}: {}".format(
            session.ip, params["port"], e))

    # Template-driven login — reads banner, detects login/password prompts
    # from template, sends credentials, verifies prompt matches template patterns
    try:
        _template_driven_login(
            conn, template,
            params.get("username", ""), params.get("password", ""),
            timeout=params.get("timeout", 30)
        )
    except BaseException:
        _close_quietly(conn)
        raise

    return conn, session


def _close_quietly(conn):
    try:
        conn.disconnect()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Interaction


# Any device asking for a password after the escalation command (enable / sudo / su) is
# answered with the privileged credential, whatever the template says (edited or imported
# templates often lack password_prompt).
DEFAULT_ESCALATION_PASSWORD_PROMPT = r"[Pp]assword:?"
ESCALATION_TIMEOUT = 15          # s for the device to answer the escalation command / password
ESCALATION_QUIET = 6.0           # s of silence before an unexpected answer counts as final


def execute_privilege_escalation(conn, template, enable_password):
    priv = (template.get("privilege_escalation") or {}) if isinstance(template, dict) else {}
    if isinstance(priv, str):
        try:
            priv = json.loads(priv) or {}
        except ValueError:
            priv = {}
    if not priv or not priv.get("command"):
        return

    cmd = priv["command"]
    # Canonical schema (command/password_prompt/success_pattern) with legacy
    # aliases (prompt_pattern/enable_prompt/prompt) so existing seeded templates
    # keep working. sudo-based escalations always require a password prompt, so
    # infer one when a (legacy) template omits it.
    password_prompt = priv.get("password_prompt") or priv.get("prompt_pattern")
    if not password_prompt and re.search(r"(^|\s)sudo\b", str(cmd)):
        password_prompt = DEFAULT_ESCALATION_PASSWORD_PROMPT
    success_pattern = priv.get("success_pattern") or priv.get("enable_prompt") or priv.get("prompt")
    needs_pw = bool(password_prompt)

    # Skip if escalation password is required but not provided
    if needs_pw and not enable_password:
        return

    # The device may ask for a password even when the template does not say so.
    pw_end = _end_re(password_prompt or DEFAULT_ESCALATION_PASSWORD_PROMPT, re.IGNORECASE)
    ok_end = _end_re(success_pattern) if success_pattern else None
    any_prompt = _end_re(build_prompt_re(template), line_start=True) if build_prompt_re(template) else None
    output = ""
    try:
        conn.write_channel(conn.normalize_cmd(cmd))
        # slow devices (GNS3, busy CPUs) may need seconds before the password prompt shows
        output, _ = _wait_for(conn, [pw_end, ok_end, any_prompt], ESCALATION_TIMEOUT,
                              unmatched_quiet=ESCALATION_QUIET)
    except Exception:
        pass

    sent_password = False
    if pw_end is not None and pw_end.search(output):
        if not enable_password:
            # never type the next command into a password prompt
            raise DeviceAuthError(
                "Device asks for a privileged (enable) password after '{}', but no privileged "
                "credential is set for this device".format(cmd))
        try:
            conn.write_channel(enable_password + "\r\n")
            post, _ = _wait_for(conn, [ok_end, any_prompt, pw_end], ESCALATION_TIMEOUT,
                                unmatched_quiet=ESCALATION_QUIET)
            output += post
            sent_password = True
        except Exception:
            pass
        tail = output[-200:]
        if pw_end.search(tail) or re.search(r"access denied|bad (password|secret)|authentication failed|incorrect",
                                             tail, re.IGNORECASE):
            if pw_end.search(tail):
                try:
                    conn.write_channel("\x03")            # leave the password prompt
                except Exception:
                    pass
            raise DeviceAuthError("Privileged (enable) password rejected after '{}': {}".format(
                cmd, output.strip()[-200:]))

    # Verify we're in privileged mode by matching the enable prompt. Hard-fail
    # only when a password was expected/supplied (a stuck sudo/enable prompt
    # would otherwise swallow the next command). Non-password escalations keep
    # the soft warning to avoid breaking devices with fuzzy success patterns.
    if success_pattern and not re.search(success_pattern, output):
        if (needs_pw and enable_password) or sent_password:
            raise DeviceCommandError(
                "Privilege escalation failed for '{}': {}".format(cmd, output.strip()[:200])
            )
        log.warning("Privilege escalation may have failed. Output: %s", output[:200])


def _send_single_line(conn, command, prompt_re, read_timeout):
    return _send_command_watch(conn, command, prompt_re, read_timeout)


def _send_multiline_exec(conn, command, prompt_re, read_timeout):
    lines = [l.strip() for l in command.splitlines() if l.strip()]
    if not lines:
        return ""
    output_parts = []
    for i, line in enumerate(lines):
        if prompt_re:
            # a question (e.g. '[y/N]:') is answered by the next line of the snippet
            out = _send_command_watch(conn, line, prompt_re, read_timeout, answer_follows=i + 1 < len(lines))
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


MAX_PAGES = 20000
_PAGER_ERASE = r"(?:\x08+[ \t]*\x08*|\x1b\[\d*D[ \t]*(?:\x1b\[\d*D)?|\n[ \t]+\n)?"


PROMPT_CONFIRM = 0.5       # seconds of silence that confirm the device is back at its prompt
# The device waits for an answer instead of finishing the command (password, [y/N], [confirm],
# 'Destination filename [startup-config]?'). Without this the job sat on the prompt until the
# read timeout (40 s - 300 s) and then reported 'Pattern not detected'.
INPUT_WAIT = (r"(?:[Pp]ass(?:word|phrase)[^\n]{0,20}:|\[(?:[yY]/[nN]|[yY]es/[nN]o|confirm)\][^\n]{0,5}"
              r"|\((?:[yY]/[nN]|[yY]es/[nN]o)\)[^\n]{0,5}|\[[^\]\n]{1,60}\]\?)")
INPUT_END = re.compile(r"(?:{})[ \t]*$".format(INPUT_WAIT))
INPUT_CONFIRM = 3.0        # seconds of silence that confirm the device really waits for input


class DeviceInputRequired(DeviceCommandError):
    """The command stopped at a question the job cannot answer."""


def _input_required(command, output):
    last = output.rstrip().rsplit("\n", 1)[-1].strip()
    return DeviceInputRequired(
        "The device waits for input after '{}': '{}'. Give the answer as the next line of the "
        "command (snippet), or use a command that asks nothing.".format(command.strip()[:80], last[:120]))


def _tail(output, size=2000):
    """End of the output, starting at a line boundary (patterns anchored with (?:^|\n) must not
    match at a cut in the middle of a line)."""
    if len(output) <= size:
        return output
    t = output[-size:]
    nl = t.find("\n")
    return t[nl:] if nl >= 0 else t


def _read_until_tail(conn, stop_re, read_timeout):
    """Read until the END of the data read in this call matches stop_re (compiled). Like
    netmiko read_until_pattern, but only the end is searched: netmiko searches all of it on
    every read, O(n^2) for big outputs."""
    out = ""
    start = time.time()
    while time.time() - start < read_timeout:
        new = conn.read_channel()
        if new:
            out += new
            if stop_re.search(_tail(out)):
                return out
        else:
            time.sleep(0.025)
    raise ReadTimeout("Pattern not detected: {!r} in output.".format(stop_re.pattern))


def _send_command_watch(conn, command, prompt_re, read_timeout, answer_follows=False):
    """netmiko send_command (same echo / prompt stripping) that also stops at an input
    prompt. Only the end of the output is searched - netmiko searches the whole output on
    every read (O(n^2) for big configs). With answer_follows (the next snippet line is the
    answer) the output so far is returned at once; otherwise a question that stays silent for
    INPUT_CONFIRM seconds raises DeviceInputRequired. Data after a look-alike (a config line
    ending in 'password:') means it was output: reading goes on."""
    if not prompt_re:
        return conn.send_command(command, read_timeout=read_timeout, cmd_verify=False)
    prompt_part = _noncapturing(prompt_re)
    prompt_tail = re.compile("(?:{})".format(prompt_part))
    command_string = conn.normalize_cmd(command)
    conn.write_channel(command_string)
    output, first_done = "", False
    start = time.time()
    while time.time() - start < read_timeout:
        new = conn.read_channel()
        if not new:
            time.sleep(0.025)
            continue
        output += new
        if not first_done:
            output, first_done = conn._first_line_handler(output, prompt_part)
        tail = _tail(output)
        if prompt_tail.search(tail):
            break
        if INPUT_END.search(tail):
            if answer_follows:
                break
            time.sleep(INPUT_CONFIRM)
            extra = conn.read_channel()
            if not extra:
                raise _input_required(command, output)
            output += extra
            if prompt_tail.search(_tail(output)):
                break
    else:
        raise ReadTimeout("Pattern not detected: {!r} in output (command '{}', {} s)".format(
            prompt_part, command.strip()[:80], read_timeout))
    return conn._sanitize_output(output, strip_command=True, command_string=command_string, strip_prompt=True)


def _handle_pagination(conn, template, command, prompt_re, read_timeout, exact_prompt=False):
    pagination = (template.get("pagination") or {}) if isinstance(template, dict) else {}
    if not pagination.get("enabled"):
        return _send_command_watch(conn, command, prompt_re, read_timeout)

    more_pattern = pagination.get("pattern", "--More--")
    more_key = pagination.get("key", "space")
    key_map = {"space": " ", "enter": "\n", "q": "q"}
    key = key_map.get(more_key, " ")
    if prompt_re:
        output = _read_paged(conn, command, prompt_re, more_pattern, key, read_timeout, exact_prompt)
    else:
        output = _read_paged_timing(conn, command, more_pattern, key, read_timeout)
    # Strip pagination control text so diffs don't show false changes
    return _strip_pagination(output, more_pattern)


def _prompt_part(prompt_re):
    """Template prompt alternatives for matching at the start of a line: groups made
    non-capturing, a leading '^' dropped (the caller anchors with (?:^|\n))."""
    nc = _noncapturing(prompt_re)
    return re.sub(r"(^|\(\?:|\|)\^", r"\1", nc)


def _current_prompt(conn, prompt_re):
    """The exact prompt the device shows now (one Enter), or None."""
    try:
        found = conn.find_prompt(pattern="(?:^|\n)(?:{})[ \t]*$".format(_prompt_part(prompt_re)))
    except Exception:
        return None
    found = (found or "").strip()
    if not found or not re.search("(?:{})".format(_prompt_part(prompt_re)), found):
        return None
    return found


def _read_paged(conn, command, prompt_re, more_pattern, key, read_timeout, exact_prompt=False):
    """Prompt-driven read of a paged command. A truncated output is never returned as a
    success:
      - the pager marker and the prompt only count at the end of what arrived so far, the
        prompt also only at the start of a line;
      - with exact_prompt (backups) the prompt is the device's own current prompt string, not
        the template regex (a config line such as a '#####' banner line or '[V200R009]' can
        match a template regex);
      - a prompt is accepted only after PROMPT_CONFIRM seconds without more data; data that
        follows a prompt-like line means it was config text and reading goes on;
      - no prompt and no marker within read_timeout raises ReadTimeout.
    """
    exact = _current_prompt(conn, prompt_re) if exact_prompt else None
    prompt_part = re.escape(exact) if exact else _prompt_part(prompt_re)
    more_part = _noncapturing(more_pattern)
    # netmiko's read_until_pattern needs exactly one capturing group around the whole pattern
    stop = re.compile("((?:{})[ \t]*$|(?:^|\n)(?:{})[ \t]*$|(?:{})[ \t]*$)".format(more_part, prompt_part, INPUT_WAIT))
    more_end = re.compile("(?:{})[ \t]*$".format(more_part))
    prompt_end = re.compile("(?:^|\n)(?:{})[ \t]*$".format(prompt_part))
    conn.write_channel(conn.normalize_cmd(command))
    output = ""
    pages = 0
    while True:
        output += _read_until_tail(conn, stop, read_timeout)
        while True:
            if more_end.search(_tail(output)):
                pages += 1
                if pages > MAX_PAGES:
                    raise DeviceCommandError("More than {} pages of output for '{}'".format(MAX_PAGES, command))
                conn.write_channel(key)
                break
            if prompt_end.search(_tail(output)):
                time.sleep(PROMPT_CONFIRM)
                extra = conn.read_channel()          # includes what read_until_pattern buffered
                if not extra:
                    return _drop_echo(output, command)
                output += extra
                continue                             # it was config text: look at the new end
            if INPUT_END.search(_tail(output)):
                time.sleep(INPUT_CONFIRM)
                extra = conn.read_channel()
                if not extra:
                    raise _input_required(command, output)
                output += extra
                continue                             # a config line that looks like a question
            break                                    # a false wake-up mid-line: read on


def _drop_echo(output, command):
    lines = output.split("\n", 1)
    if command.strip() and command.strip() in lines[0]:
        return lines[1] if len(lines) > 1 else ""
    return output


_CAPTURE_OPEN = re.compile(r"(?<!\\)\((?:\?P<\w+>)?(?!\?)")


def _noncapturing(pattern):
    """Turn capturing groups of a template pattern into non-capturing ones."""
    return _CAPTURE_OPEN.sub("(?:", pattern or "")


def _read_paged_timing(conn, command, more_pattern, key, read_timeout):
    """Template without prompt patterns: quiet-period reads (each page kept)."""
    output = conn.send_command_timing(command, read_timeout=read_timeout)
    for _ in range(MAX_PAGES):
        if not re.search("(?:{})[ \t]*$".format(more_pattern), output.rstrip("\n")):
            break
        conn.write_channel(key)
        try:
            more = conn.read_channel_timing(read_timeout=read_timeout)
        except ReadTimeout:
            more = ""
        if not more:
            break
        output += more
    return output


def _strip_pagination(output, pattern):
    """Remove the pager markers and the terminal erase sequence that follows them (Cisco:
    backspaces, Huawei: ESC[42D, Juniper: CR + spaces + CR). Text that follows a marker on
    the same line is the next page and is kept."""
    if not output or not pattern:
        return output or ""
    return re.sub("[ \t]*(?:{})[ \t]*{}".format(pattern, _PAGER_ERASE), "", output)


def _strip_trailing_prompt(output, prompt_re=None):
    """Strip trailing device CLI prompt and trailing blank lines from command output.
    With a template prompt only that prompt is stripped: the generic look-alikes removed a
    last output line such as Cisco's '[OK]'."""
    if not output:
        return ""
    lines = output.rstrip().splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        last = lines[-1].strip()
        matched = False
        if prompt_re and re.search(prompt_re, last):
            matched = True
        elif not prompt_re and re.search(r"^(?:\[[^\]\r\n]+@[^\]\r\n]+\][^\r\n]*?[>#]|\S+[@#>$]|\<[\w\-]+\>|\[[\w\-]+\])\s*$", last):
            matched = True
        if matched:
            lines.pop()
            while lines and not lines[-1].strip():
                lines.pop()
            return "\n".join(lines)
    return output


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


def export_flags_for_version(version):
    """'{export_flags}' of the MikroTik templates for a RouterOS version string, or None."""
    m = re.match(r"^\s*(\d+)\.", str(version or ""))
    if not m:
        return None
    return " show-sensitive" if int(m.group(1)) >= 7 else ""


def _resolve_export_flags_ssh(conn, command, prompt_re=None):
    """Fallback: detect RouterOS version over SSH to resolve {export_flags}.

    Used when neither the routeros_api pre_connect hook nor the stored firmware version
    gave it. Resolution order: hook -> stored version -> SSH version detection -> ''.
    """
    flags = ""
    try:
        conn.write_channel(conn.normalize_cmd(":put [/system resource get version]"))
        if prompt_re:
            out, _ = _wait_for(conn, [_end_re(prompt_re, line_start=True)], 10)
        else:
            out = conn.read_channel_timing(read_timeout=10) or ""
        m = re.search(r"(?m)^\s*(\d+)\.\d+", out)
        if m:
            flags = " show-sensitive" if int(m.group(1)) >= 7 else ""
    except Exception:
        flags = ""
    return command.replace("{export_flags}", flags)


def execute_command(conn, command, template, prompt_re, is_config_mode, enable_password, read_timeout,
                    exact_prompt=False):
    """:returns (output, duration_ms)

    exact_prompt: paged output ends only at the device's own current prompt (backups -
    the prompt does not change during 'show running-config' and alike)."""
    start = time.time()

    prompt_end = _end_re(prompt_re, line_start=True) if prompt_re else None
    for cmd in (template.get("post_login_commands") or []):
        try:
            if prompt_end is not None:
                conn.write_channel(conn.normalize_cmd(cmd))
                _wait_for(conn, [prompt_end], 5)
            else:
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
        output = _handle_pagination(conn, template, clean_command, prompt_re, read_timeout, exact_prompt)

    if _is_login_failure(output):
        raise DeviceAuthError("Login failed: {}".format(output.strip()[:200]))

    _scan_errors(output, template)
    output = _strip_trailing_prompt(output, prompt_re)
    duration_ms = int((time.time() - start) * 1000)
    return output, duration_ms


def disconnect_device(conn, template):
    """Send the template's logout commands (their answers do not matter) and close."""
    for cmd in (template.get("pre_logout_commands") or []):
        try:
            conn.write_channel(conn.normalize_cmd(cmd))
            time.sleep(0.15)
            conn.read_channel()
        except Exception:
            pass
    try:
        conn.disconnect()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# MikroTik non-interactive SSH (exec channel): one request, output until the channel closes.
# No banner, prompt, echo or quiet-period reads (~0.1 s instead of seconds per device).


class ExecChannelUnavailable(DeviceConnectionError):
    """Logged in, but the router refused the exec request: the interactive session is used."""


def use_exec_channel(template, session, command, is_config_mode, keep_session, session_conn, backup=False):
    """True when this command runs over the exec channel (PYSRV_MIKROTIK_EXEC: 'template' =
    templates flagged connection.is_non_interactive, 'all' = every MikroTik, 'off').
    Backups only: over exec RouterOS asks no confirmations ('/system reboot' would run where
    the interactive session stops at [y/N]), so snippets always use the interactive session."""
    mode = str(getattr(config, "MIKROTIK_EXEC", "template") or "template").lower()
    if not backup or mode == "off" or session is None or keep_session or session_conn is not None or is_config_mode:
        return False
    if (session.brand or "").lower() != "mikrotik" or session.protocol != "ssh":
        return False
    if not command or "\n" in command.strip():
        return False
    if mode == "all":
        return True
    conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
    return bool(conn_conf.get("is_non_interactive"))


def exec_channel_command(session, command, port, connect_timeout, read_timeout):
    """Run one command over an SSH exec channel. Returns the output ('\n' line ends,
    trailing whitespace removed). Raises DeviceAuthError / DeviceTimeoutError /
    DeviceConnectionError."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(session.ip, port=int(port), username=session.username, password=session.password,
                           timeout=connect_timeout, banner_timeout=connect_timeout, auth_timeout=connect_timeout,
                           look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException as e:
            raise DeviceAuthError("Auth failed for {}: {}".format(session.ip, e))
        except (socket.timeout, TimeoutError) as e:
            raise DeviceTimeoutError("Timeout connecting to {}:{}: {}".format(session.ip, port, e))
        except (socket.error, EOFError, paramiko.SSHException) as e:
            raise DeviceConnectionError("Connection error for {}:{}: {}".format(session.ip, port, e))
        try:
            chan = client.get_transport().open_session(timeout=connect_timeout)
            chan.settimeout(read_timeout)
            chan.exec_command(command)
        except (socket.timeout, EOFError, OSError, paramiko.SSHException) as e:
            raise ExecChannelUnavailable("SSH exec request refused by {}: {}".format(session.ip, e))
        try:
            chunks = []
            deadline = time.time() + read_timeout
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if time.time() > deadline:
                    raise DeviceTimeoutError("Output of '{}' did not end within {} s".format(command, read_timeout))
            # recv() also returns b"" when the connection drops (router reboot, TCP reset).
            # A real end is an EOF, an exit status or the server's CHANNEL_CLOSE - RouterOS
            # sends only the CLOSE (no EOF, no exit status). paramiko answers a received CLOSE
            # with its own EOF (eof_sent); a dropped connection only marks the channel closed.
            chan.status_event.wait(0.5)
            if not (chan.eof_received or chan.exit_status != -1 or (chan.closed and chan.eof_sent)):
                raise DeviceConnectionError("Connection to {} lost before the output ended ({} bytes received)".format(
                    session.ip, sum(len(c) for c in chunks)))
            chan.status_event.wait(5)
        except socket.timeout:
            raise DeviceTimeoutError("No output from {} for {} s".format(session.ip, read_timeout))
        except (EOFError, OSError, paramiko.SSHException) as e:
            raise DeviceConnectionError("Connection to {} lost: {}".format(session.ip, e))
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return text.replace("\r\n", "\n").replace("\r", "\n").rstrip()
    finally:
        try:
            client.close()
        except Exception:
            pass


def _exec_port(template, session, hook_context):
    port = hook_context.get("ssh_port") if hook_context else None
    if not port:
        port = session.port
    if not port:
        conn_conf = (template.get("connection") or {}) if isinstance(template, dict) else {}
        port = conn_conf.get("default_port_ssh", 22)
    return int(port)


def connect_and_execute(device_id, command, template_id=None, template=None,
                        hook_context=None, legacy_creds=None,
                        prompt_re=None, is_config_mode=False, enable_password=None,
                        timeout=60, session_conn=None, keep_session=False, session=None,
                        exact_prompt=False):
    """Single-attempt connect → execute → disconnect.  Retry is the caller's job.

    session (DeviceSession from resolve_session): connection data resolved beforehand, so
    nothing here touches the database while the router is being talked to. Without it the
    data is read here (legacy callers).
    If session_conn is provided, reuse it (skip connect/disconnect - the caller owns it).
    If keep_session is True, keep the connection open and return it for reuse.
    A connection opened here is always closed when the call fails.

    :returns dict(output, duration_ms, error, error_type, session_conn)
    """
    conn_obj = session_conn
    opened_here = False
    try:
        # with a resolved session the caller already chose the template (possibly none)
        if not template and template_id and session is None:
            template = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        if not template and device_id and session is None:
            dev_obj = Devices.get_or_none(Devices.id == device_id)
            if dev_obj:
                brand = getattr(dev_obj, "device_type", None) or "mikrotik"
                template = get_template_for_brand(brand)
        if not template:
            template = {}
        if not isinstance(template, dict):
            template = _peewee_dict(template)

        if session is None:
            session = resolve_session(Devices.get_by_id(device_id), get_cli_connection(device_id), legacy_creds)

        if not prompt_re:
            prompt_re = build_prompt_re(template)

        if not enable_password:
            enable_password = session.enable_password

        if use_exec_channel(template, session, command, is_config_mode, keep_session, session_conn,
                            backup=exact_prompt):
            conn_conf = template.get("connection") or {}
            connect_timeout = conn_conf.get("timeout", 30)
            port = _exec_port(template, session, hook_context)
            start = time.time()
            try:
                exec_command = command
                if "{export_flags}" in exec_command:
                    flags = export_flags_for_version(session.firmware)
                    if flags is None:
                        flags = export_flags_for_version(exec_channel_command(
                            session, ":put [/system resource get version]", port, connect_timeout, 30)) or ""
                    exec_command = exec_command.replace("{export_flags}", flags)
                output = exec_channel_command(session, exec_command, port, connect_timeout, timeout)
                _scan_errors(output, template)
                return {"output": output, "duration_ms": int((time.time() - start) * 1000), "error": None,
                        "error_type": None, "session_conn": None}
            except ExecChannelUnavailable as e:
                log.warning("%s - using the interactive session", e)

        if conn_obj is None:
            conn_obj, _ = connect_device(device_id, template, None, hook_context, legacy_creds, session=session)
            opened_here = True

        # Resolve any remaining {export_flags}: stored firmware version, else over SSH.
        if command and "{export_flags}" in command:
            flags = export_flags_for_version(getattr(session, "firmware", None))
            if flags is not None:
                command = command.replace("{export_flags}", flags)
            else:
                command = _resolve_export_flags_ssh(conn_obj, command, prompt_re)

        output, duration_ms = execute_command(
            conn_obj, command, template, prompt_re, is_config_mode, enable_password, timeout,
            exact_prompt=exact_prompt,
        )
        if keep_session:
            return {"output": output, "duration_ms": duration_ms, "error": None, "error_type": None,
                    "session_conn": conn_obj}
        if opened_here:
            disconnect_device(conn_obj, template)
            opened_here = False
        return {"output": output, "duration_ms": duration_ms, "error": None, "error_type": None,
                "session_conn": session_conn}

    except DeviceAuthError as e:
        return _failed(conn_obj, opened_here, str(e), "auth")
    except (DeviceTimeoutError, ReadTimeout, socket.timeout) as e:
        return _failed(conn_obj, opened_here, str(e) or "read timeout", "timeout")
    except DeviceCommandError as e:
        output = None
        try:
            if conn_obj:
                output = conn_obj.read_channel_timing(read_timeout=2)
        except Exception:
            pass
        res = _failed(conn_obj, opened_here, str(e), "command")
        res["output"] = output
        return res
    except (DeviceConnectionError, EOFError, OSError, paramiko.SSHException) as e:
        return _failed(conn_obj, opened_here, str(e) or type(e).__name__, "connection")
    except Exception as e:
        log.exception("Unexpected connect_and_execute error for device %s", device_id)
        return _failed(conn_obj, opened_here, str(e), "unknown")


def _failed(conn_obj, opened_here, message, error_type):
    """A connection opened by this call is closed (not reused: its state is unknown)."""
    if opened_here and conn_obj is not None:
        _close_quietly(conn_obj)
    return {"output": None, "duration_ms": 0, "error": message, "error_type": error_type, "session_conn": None}
