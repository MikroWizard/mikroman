#!/usr/bin/python
# -*- coding: utf-8 -*-

# fw_state.py: per-device firmware update lease and update record (Redis)
# MikroWizard.com , Mikrotik router management solution
#
# Lease  mw:fw:lease:<dev_id>   one owner at a time works on a device (spooler, firmware
#                               mule, scheduled task). Short TTL, refreshed by a heartbeat
#                               thread while the owner process is alive, so a killed process
#                               (harakiri, OOM, restart) frees its devices within LEASE_TTL.
# Record mw:fw:rec:<dev_id>     what was done / what is expected for the device:
#                               state queued | rebooting | next_step, final + step target,
#                               reboot time, uptime/packages before, request options.
#                               Lets the firmware mule verify, continue multi-step upgrades
#                               and recover after restarts.

import json
import logging
import os
import socket
import threading
import time
import uuid

from libs.red import RedisDB

log = logging.getLogger("fw_state")

LEASE_KEY = "mw:fw:lease:{}"
RECORD_KEY = "mw:fw:rec:{}"
QUEUE_SEQ_KEY = "mw:fw:queue_seq"
LEASE_TTL = 300                 # seconds without heartbeat before a lease is free again
HEARTBEAT_INTERVAL = 60
RECORD_TTL = 30 * 24 * 3600

_RELEASE_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end
"""
_REFRESH_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end
"""

_held = {}                      # dev_id -> token (leases held by this process)
_held_lock = threading.Lock()
_hb_thread = None
_hb_pid = None


def _redis():
    return RedisDB({}).r


def _decode(v):
    return v.decode() if isinstance(v, bytes) else v


def owner_token():
    return "{}:{}:{}:{}".format(socket.gethostname(), os.getpid(), threading.get_ident(), uuid.uuid4().hex[:8])


def _ensure_heartbeat():
    """One daemon thread per process refreshes every lease this process holds."""
    global _hb_thread, _hb_pid
    if _hb_thread is not None and _hb_thread.is_alive() and _hb_pid == os.getpid():
        return
    with _held_lock:
        if _hb_thread is not None and _hb_thread.is_alive() and _hb_pid == os.getpid():
            return
        if _hb_pid != os.getpid():
            _held.clear()          # forked child: the parent's leases are not ours
        _hb_pid = os.getpid()
        _hb_thread = threading.Thread(target=_heartbeat_loop, name="fw-lease-heartbeat", daemon=True)
        _hb_thread.start()


def _heartbeat_loop():
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        refresh_all()


def refresh_all():
    with _held_lock:
        items = list(_held.items())
    if not items:
        return 0
    refreshed = 0
    try:
        r = _redis()
        for dev_id, token in items:
            try:
                if r.eval(_REFRESH_LUA, 1, LEASE_KEY.format(dev_id), token, LEASE_TTL):
                    refreshed += 1
                else:
                    log.error("Firmware lease for device %s was lost", dev_id)
                    with _held_lock:
                        if _held.get(dev_id) == token:
                            _held.pop(dev_id, None)
            except Exception as e:
                log.warning("Could not refresh firmware lease of device %s: %s", dev_id, e)
    except Exception as e:
        log.warning("Firmware lease heartbeat: redis unavailable: %s", e)
    return refreshed


def acquire(dev_id, ttl=LEASE_TTL):
    """Take the device lease. Returns a token, or None when another owner holds it (or
    Redis is unreachable - no work without a lease)."""
    token = owner_token()
    try:
        ok = _redis().set(LEASE_KEY.format(dev_id), token, nx=True, ex=int(ttl))
    except Exception as e:
        log.error("Firmware lease for device %s not taken (redis error): %s", dev_id, e)
        return None
    if not ok:
        return None
    _ensure_heartbeat()          # may reset _held after a fork: must run before registering
    with _held_lock:
        _held[dev_id] = token
    return token


def release(dev_id, token):
    if not token:
        return False
    with _held_lock:
        if _held.get(dev_id) == token:
            _held.pop(dev_id, None)
    try:
        return bool(_redis().eval(_RELEASE_LUA, 1, LEASE_KEY.format(dev_id), token))
    except Exception as e:
        log.warning("Could not release firmware lease of device %s: %s", dev_id, e)
        return False


def is_leased(dev_id):
    try:
        return bool(_redis().exists(LEASE_KEY.format(dev_id)))
    except Exception:
        return True       # unknown: treat as busy (never start a second worker)


def leased_ids(dev_ids):
    """Subset of dev_ids that currently have a lease (one round trip)."""
    dev_ids = list(dev_ids)
    if not dev_ids:
        return set()
    try:
        pipe = _redis().pipeline()
        for d in dev_ids:
            pipe.exists(LEASE_KEY.format(d))
        return {d for d, e in zip(dev_ids, pipe.execute()) if e}
    except Exception:
        return set(dev_ids)


def expect_offline(dev_id):
    """True while a firmware operation may legitimately make the router unreachable
    (worker active, or reboot sent and not verified yet). A device that is only queued is
    not expected to be offline - its unreachable alerts must not be hidden."""
    try:
        r = _redis()
        if r.exists(LEASE_KEY.format(dev_id)):
            return True
        raw = r.get(RECORD_KEY.format(dev_id))
        if not raw:
            return False
        return json.loads(_decode(raw)).get("state") in ("rebooting", "transferring")
    except Exception:
        return True


class Lease(object):
    """with Lease(dev_id) as ok: ... (ok is False when the device is busy)."""

    def __init__(self, dev_id):
        self.dev_id = dev_id
        self.token = None

    def __enter__(self):
        self.token = acquire(self.dev_id)
        return self.token is not None

    def __exit__(self, *exc):
        release(self.dev_id, self.token)
        return False


# ---------------------------------------------------------------------------
# Update record
# ---------------------------------------------------------------------------

def get_record(dev_id):
    try:
        raw = _redis().get(RECORD_KEY.format(dev_id))
    except Exception as e:
        log.warning("Could not read firmware record of device %s: %s", dev_id, e)
        return None
    if not raw:
        return None
    try:
        return json.loads(_decode(raw))
    except Exception:
        return None


def get_records(dev_ids):
    dev_ids = list(dev_ids)
    if not dev_ids:
        return {}
    try:
        values = _redis().mget([RECORD_KEY.format(d) for d in dev_ids])
    except Exception as e:
        log.warning("Could not read firmware records: %s", e)
        return {}
    out = {}
    for d, raw in zip(dev_ids, values):
        if raw:
            try:
                out[d] = json.loads(_decode(raw))
            except Exception:
                pass
    return out


def put_record(dev_id, record):
    record = dict(record)
    record["updated_at"] = time.time()
    try:
        _redis().set(RECORD_KEY.format(dev_id), json.dumps(record), ex=RECORD_TTL)
        return True
    except Exception as e:
        log.error("Could not store firmware record of device %s: %s", dev_id, e)
        return False


def update_record(dev_id, **fields):
    rec = get_record(dev_id) or {}
    rec.update(fields)
    return put_record(dev_id, rec)


def clear_record(dev_id):
    try:
        _redis().delete(RECORD_KEY.format(dev_id))
    except Exception as e:
        log.warning("Could not clear firmware record of device %s: %s", dev_id, e)


def next_queue_seq():
    try:
        return int(_redis().incr(QUEUE_SEQ_KEY))
    except Exception:
        return int(time.time() * 1000)
