#!/usr/bin/python
# -*- coding: utf-8 -*-

# device_trust.py: optional verification of router identities (opt-in, default off)
#   API-SSL: 'device_tls_verify' = off | pin (certificate fingerprint trusted on first use) |
#            ca (verified against 'device_tls_cafile')
#   SSH:     'device_ssh_verify' = off | pin (host key trusted on first use)
# A changed certificate / host key is refused and reported as a Critical device event until an
# admin resets the trust of that device. Without migration 066 (table device_trust) the pin modes
# do nothing: everything works as with 'off'.
# MikroWizard.com , Mikrotik router management solution

import contextlib
import datetime
import hashlib
import logging
import threading
import time

from peewee import DateTimeField, IntegerField, TextField

from libs.db import db_events, db_sysconfig
from libs.db.db import BaseModel, database

log = logging.getLogger("device_trust")

MODE_TTL = 30            # s a mode setting is cached per process
PIN_TTL = 60             # s a stored pin is cached per process
TLS, SSH = "tls", "ssh"
_lock = threading.Lock()
_modes = {}              # key -> (value, read_at)
_pins = {}               # (device_id, kind) -> (value, read_at)
_table_ok = {"value": None, "checked_at": 0.0}


class DeviceTrust(BaseModel):
    device_id = IntegerField(primary_key=True)
    tls_fingerprint = TextField(null=True)
    tls_seen_at = DateTimeField(null=True)
    ssh_host_key = TextField(null=True)
    ssh_seen_at = DateTimeField(null=True)

    class Meta:
        db_table = "device_trust"


class TrustError(Exception):
    """The router presented another certificate / host key than the trusted one."""


def _db():
    """A DB connection for a short query, without closing one the caller already holds."""
    return database.connection_context() if database.is_closed() else contextlib.nullcontext()


def _setting(key, default):
    now = time.time()
    with _lock:
        hit = _modes.get(key)
        if hit and now - hit[1] < MODE_TTL:
            return hit[0]
    try:
        with _db():
            value = db_sysconfig.get_sysconfig(key)
    except Exception as e:
        log.warning("setting %s not readable: %s", key, e)
        value = None
    value = (value or default).strip() if isinstance(value or default, str) else default
    with _lock:
        _modes[key] = (value, now)
    return value


def tls_mode():
    mode = _setting("device_tls_verify", "off").lower()
    return mode if mode in ("off", "pin", "ca") else "off"


def ssh_mode():
    mode = _setting("device_ssh_verify", "off").lower()
    return mode if mode in ("off", "pin") else "off"


def tls_cafile():
    return _setting("device_tls_cafile", "") or None


def _table_ready():
    now = time.time()
    if _table_ok["value"] is not None and now - _table_ok["checked_at"] < 300:
        return _table_ok["value"]
    try:
        with _db():
            ok = DeviceTrust.table_exists()
    except Exception:
        ok = False
    if not ok and _table_ok["value"] is not False:
        log.warning("device_trust table missing (run migration 066): certificate / host-key pinning is inactive")
    _table_ok.update(value=ok, checked_at=now)
    return ok


def _column(kind):
    return (DeviceTrust.tls_fingerprint, DeviceTrust.tls_seen_at) if kind == TLS else \
        (DeviceTrust.ssh_host_key, DeviceTrust.ssh_seen_at)


def _stored(device_id, kind):
    now = time.time()
    with _lock:
        hit = _pins.get((device_id, kind))
        if hit and now - hit[1] < PIN_TTL:
            return hit[0]
    with _db():
        row = DeviceTrust.get_or_none(DeviceTrust.device_id == device_id)
    value = getattr(row, _column(kind)[0].name) if row else None
    with _lock:
        _pins[(device_id, kind)] = (value, now)
    return value


def _store(device_id, kind, value):
    col, seen = _column(kind)
    now = datetime.datetime.now(datetime.timezone.utc)
    with _db():
        DeviceTrust.insert(device_id=device_id, **{col.name: value, seen.name: now}).on_conflict(
            conflict_target=[DeviceTrust.device_id], update={col: value, seen: now}).execute()
    with _lock:
        _pins[(device_id, kind)] = (value, time.time())


def check(kind, device_id, fingerprint):
    """Trust on first use: the first fingerprint of a device is stored, a different one later
    raises TrustError (and a Critical device event). No-op when the mode is not 'pin'."""
    mode = tls_mode() if kind == TLS else ssh_mode()
    if mode != "pin" or not device_id or not fingerprint or not _table_ready():
        return
    try:
        stored = _stored(device_id, kind)
    except Exception as e:
        log.warning("device %s: trusted %s not readable (%s) - not checked", device_id, kind, e)
        return
    if not stored:
        try:
            _store(device_id, kind, fingerprint)
            log.info("device %s: %s %s trusted on first use", device_id, "certificate" if kind == TLS else "host key",
                     fingerprint)
        except Exception as e:
            log.warning("device %s: %s pin not saved: %s", device_id, kind, e)
        return
    if stored == fingerprint:
        return
    what = "API-SSL certificate" if kind == TLS else "SSH host key"
    detail = "{} changed".format(what)
    try:
        with _db():
            db_events.state_event(device_id, "Device Trust", detail, "Critical", 0,
                                  "Trusted {} expected, router presented {}. Connection refused - if the change is "
                                  "expected, reset the device trust.".format(stored, fingerprint))
    except Exception as e:
        log.warning("device %s: trust event not saved: %s", device_id, e)
    raise TrustError("{} of the router changed (trusted {}, got {}): connection refused. "
                     "Reset the device trust if the change is expected.".format(what, stored, fingerprint))


def reset(device_id, kind=None):
    """Forget the trusted certificate and/or host key: the next connection is trusted again."""
    if not _table_ready():
        return False
    update = {}
    if kind in (None, TLS):
        update.update({DeviceTrust.tls_fingerprint: None, DeviceTrust.tls_seen_at: None})
    if kind in (None, SSH):
        update.update({DeviceTrust.ssh_host_key: None, DeviceTrust.ssh_seen_at: None})
    with _db():
        DeviceTrust.update(update).where(DeviceTrust.device_id == device_id).execute()
        db_events.Events.update(status=True).where(
            db_events.Events.devid == device_id, db_events.Events.src == "Device Trust",
            db_events.Events.status == False).execute()  # noqa: E712 - peewee expression
    with _lock:
        for k in (TLS, SSH):
            _pins.pop((device_id, k), None)
    return True


def status(device_id):
    if not _table_ready():
        return None
    with _db():
        row = DeviceTrust.get_or_none(DeviceTrust.device_id == device_id)
    if not row:
        return {"tls_fingerprint": None, "ssh_host_key": None}
    return {"tls_fingerprint": row.tls_fingerprint, "tls_seen_at": str(row.tls_seen_at or ""),
            "ssh_host_key": row.ssh_host_key, "ssh_seen_at": str(row.ssh_seen_at or "")}


# ---------------------------------------------------------------------------
# fingerprints

def tls_fingerprint(ssl_sock):
    """SHA-256 of the router's certificate (DER), None when it presented none (ADH)."""
    try:
        der = ssl_sock.getpeercert(binary_form=True)
    except Exception:
        der = None
    if not der:
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def ssh_fingerprint(key):
    """'<type> SHA256:<hex>' of a paramiko host key."""
    if key is None:
        return None
    return "{} SHA256:{}".format(key.get_name(), hashlib.sha256(key.asbytes()).hexdigest())


def tls_checker(device_id):
    """Callable for the API connection: checks the certificate right after the TLS handshake."""
    def _check(ssl_sock):
        check(TLS, device_id, tls_fingerprint(ssl_sock))
    return _check


def check_ssh_transport(device_id, transport):
    """Check the host key of an authenticated paramiko transport (TrustError on mismatch)."""
    if ssh_mode() != "pin" or not device_id or transport is None:
        return
    check(SSH, device_id, ssh_fingerprint(transport.get_remote_server_key()))
