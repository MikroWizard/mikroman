#!/usr/bin/python
# -*- coding: utf-8 -*-

# task_tracker.py: track which uWSGI spooler process runs which background task,
# so /api/tasks/stop can stop exactly that task (and not a random idle spooler).
# MikroWizard.com , Mikrotik router management solution

import fcntl
import functools
import json
import logging
import os
import signal as os_signal
import struct
import time

from libs.red import RedisDB
from libs.db import db_tasks
from libs.db.db import database

try:
    import uwsgi
except ImportError:
    uwsgi = None

log = logging.getLogger("task_tracker")

RUNNING_KEY = "mw:running_task::{}"
RUNNING_TTL = 6 * 3600

# Background task signal -> spool function names (bgtasks.py / bgtasks_non_mikrotik.py)
SIGNAL_FUNC_MAP = {
    100: ["check_devices_for_update"],
    110: ["update_device"],
    120: ["backup_devices"],
    130: ["scan_with_mac", "scan_with_ip"],
    140: ["download_firmware"],
    160: ["exec_snipet"],
    170: ["exec_vault"],
    175: ["exec_sequence"],
    180: ["bulk_add_devices", "bulk_add_non_mikrotik_devices"],
    185: ["exec_multi_brand"],
}

# Stop policy
# -----------
# Every stop is cooperative first: queued runs are removed, the running task gets
# action='cancel', its workers finish the device they are on and skip the rest. Killing a
# spooler mid-task can leave routers half-configured (snippets, vault password rotation)
# or half-upgraded, so a kill only happens when the operator presses Stop again after
# FORCE_KILL_GRACE seconds (task looks hung) or sends force=true - and never for the
# signals in NEVER_KILL.
NEVER_KILL_SIGNALS = {110, 130, 140, 170}   # firmware update, scan, firmware download, vault
FORCE_KILL_GRACE = 120                      # seconds between first Stop and allowed kill
CANCEL_KEY = "mw:cancel_requested::{}"
CANCEL_KEY_TTL = 24 * 3600
CANCEL_CACHE_SECONDS = 2.0
_cancel_cache = {}

# Backward compatible name (cooperative-only signals)
COOPERATIVE_SIGNALS = NEVER_KILL_SIGNALS


def _redis():
    return RedisDB({}).r


# ---------------------------------------------------------------------------
# Spooler side
# ---------------------------------------------------------------------------

def track_task(task_signal):
    """Decorator for @spool functions: records this spooler PID as the runner of the task
    while it executes, and clears a leftover 'cancel' flag when it exits so a stop request
    never swallows the next scheduled run of the same task.

    Usage (order matters, track_task must be the inner decorator):
        @spool(pass_arguments=True)
        @track_task(120)
        def backup_devices(*args, **kwargs): ...
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            task_id = str(kwargs.get("task_id") or "")
            field = "{}:{}".format(task_id or "_", os.getpid())
            key = RUNNING_KEY.format(task_signal)
            try:
                r = _redis()
                r.hset(key, field, json.dumps({"pid": os.getpid(), "started": time.time(),
                                               "task_id": task_id, "field": field}))
                r.expire(key, RUNNING_TTL)
            except Exception as e:
                log.warning("task_tracker: could not register task %s: %s", task_signal, e)
            try:
                return fn(*args, **kwargs)
            finally:
                try:
                    _redis().hdel(key, field)
                except Exception as e:
                    log.warning("task_tracker: could not unregister task %s: %s", task_signal, e)
                # Only clear the cancel flag when no other instance of this task is still running
                # (a duplicate trigger that exits early must not wipe a pending cancel).
                still_running = [e for e in get_running(task_signal)
                                 if str(e.get("task_id") or "") == task_id]
                if not still_running:
                    clear_cancel_flag(task_signal, task_id or None)
        return wrapper
    return deco


def clear_cancel_flag(task_signal, task_id=None):
    """Reset a leftover action='cancel' once the task has exited."""
    try:
        T = db_tasks.Tasks
        cond = (T.signal == task_signal) & (T.action == "cancel")
        if task_id:
            cond = cond & (T.task_id == str(task_id))
        with database.connection_context():
            T.update(action="None").where(cond).execute()
    except Exception as e:
        log.warning("task_tracker: could not clear cancel flag for %s: %s", task_signal, e)
    try:
        _redis().delete(CANCEL_KEY.format(task_signal))
    except Exception:
        pass
    _cancel_cache.pop((task_signal, task_id or None), None)


def cancel_requested(task_signal, task_id=None, now=None):
    """True when the operator asked to stop this task (task row action == 'cancel').

    Cheap enough to call before every device in a worker pool: the answer is cached for
    CANCEL_CACHE_SECONDS per (signal, task_id). Errors never stop a task.
    """
    now = time.time() if now is None else now
    key = (task_signal, task_id or None)
    hit = _cancel_cache.get(key)
    if hit and now - hit[0] < CANCEL_CACHE_SECONDS:
        return hit[1]
    result = False
    try:
        T = db_tasks.Tasks
        cond = (T.signal == task_signal) & (T.action == "cancel")
        if task_id:
            cond = cond & (T.task_id == str(task_id))
        with database.connection_context():
            result = T.select(T.id).where(cond).exists()
    except Exception as e:
        log.warning("task_tracker: cancel check failed for %s: %s", task_signal, e)
        result = hit[1] if hit else False
    _cancel_cache[key] = (now, result)
    return result


# ---------------------------------------------------------------------------
# API side
# ---------------------------------------------------------------------------

def get_running(task_signal):
    """[{pid, started, task_id}] registered for a signal."""
    try:
        raw = _redis().hgetall(RUNNING_KEY.format(task_signal)) or {}
    except Exception as e:
        log.warning("task_tracker: redis unavailable: %s", e)
        return []
    out = []
    for _, v in raw.items():
        try:
            out.append(json.loads(v.decode() if isinstance(v, bytes) else v))
        except Exception:
            continue
    return out


def forget_running(task_signal, field):
    try:
        _redis().hdel(RUNNING_KEY.format(task_signal), field)
    except Exception:
        pass


def spooler_pids():
    """Live spooler PIDs from uWSGI, or None when unknown (not running under uWSGI)."""
    if uwsgi is None:
        return None
    for name in ("spooler_pids",):
        fn = getattr(uwsgi, name, None)
        if callable(fn):
            try:
                return set(int(p) for p in fn())
            except Exception:
                return None
    return None


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True


def is_safe_to_kill(pid, known_spoolers):
    """Only kill a PID that is alive, is not us, and (when uWSGI tells us) is a spooler."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 1 or pid == os.getpid():
        return False
    if not pid_alive(pid):
        return False
    if known_spoolers is not None and pid not in known_spoolers:
        return False
    return True


def parse_spool_file(blob):
    """Parse a uWSGI spool file into {key: value} (bytes). Returns {} when unparseable.

    Format: 4-byte uwsgi packet header (modifier1, uint16 size LE, modifier2) followed by
    repeated (uint16 LE key length, key, uint16 LE value length, value).
    """
    out = {}
    if not blob or len(blob) < 4:
        return out
    pos = 4
    n = len(blob)
    try:
        while pos + 2 <= n:
            (klen,) = struct.unpack_from("<H", blob, pos)
            pos += 2
            if pos + klen + 2 > n:
                break
            key = bytes(blob[pos:pos + klen])
            pos += klen
            (vlen,) = struct.unpack_from("<H", blob, pos)
            pos += 2
            if pos + vlen > n:
                break
            out[key] = bytes(blob[pos:pos + vlen])
            pos += vlen
    except struct.error:
        return out
    return out


def spool_file_matches(blob, func_names, task_id=None):
    """True when a spool file belongs to one of func_names (and to task_id, when given)."""
    if not func_names:
        return False
    names = {n.encode() if isinstance(n, str) else n for n in func_names}
    parsed = parse_spool_file(blob)
    func = parsed.get(b"ud_spool_func")
    if func is not None:
        matched = func in names
    else:
        # Unknown layout: fall back to an exact token match on the function name.
        matched = any((b"ud_spool_func" in blob and n in blob) for n in names)
    if not matched:
        return False
    if task_id:
        return str(task_id).encode() in blob
    return True


def spool_file_in_use(path):
    """True when a uWSGI spooler holds the POSIX lock uWSGI takes while executing a spool file."""
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def spool_dir():
    try:
        if uwsgi is not None and hasattr(uwsgi, "opt"):
            v = uwsgi.opt.get("spooler", b"/tmp/my_spooler")
            if isinstance(v, (list, tuple)):
                v = v[0]
            return v.decode() if isinstance(v, bytes) else str(v)
    except Exception:
        pass
    return "/tmp/my_spooler"


def remove_queued_spool_files(task_signal, task_id=None, directory=None):
    """Delete pending spool files of this task so uWSGI never (re)runs them."""
    directory = directory or spool_dir()
    funcs = SIGNAL_FUNC_MAP.get(task_signal, [])
    removed = []
    if not funcs or not os.path.isdir(directory):
        return removed
    for f in os.listdir(directory):
        fp = os.path.join(directory, f)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, "rb") as sf:
                blob = sf.read(65536)
            if not spool_file_matches(blob, funcs, task_id):
                continue
            if spool_file_in_use(fp):
                # A spooler is executing this file right now. uWSGI unlinks it when the task
                # returns and exits the spooler ("something horrible happened...") if it is
                # already gone - so never delete a running task's file; the running instance
                # is stopped by SIGTERM / cancel flag instead.
                continue
            os.remove(fp)
            removed.append(fp)
        except FileNotFoundError:
            continue
        except Exception as e:
            log.warning("task_tracker: could not inspect spool file %s: %s", fp, e)
    return removed


def _mark_cancel_requested(task_signal, now):
    """Remember when Stop was first pressed; returns that first timestamp."""
    try:
        r = _redis()
        key = CANCEL_KEY.format(task_signal)
        if r.set(key, str(now), nx=True, ex=CANCEL_KEY_TTL):
            return now
        raw = r.get(key)
        return float(raw.decode() if isinstance(raw, bytes) else raw)
    except Exception:
        return now


def stop_task(task_signal, task_id=None, kill=os.kill, force=False, now=None):
    """Stop a background task.

    1. Remove its queued (not yet running) spool files.
    2. Set action='cancel' on the RUNNING row(s): workers finish the device in progress and
       skip the remaining ones; track_task clears the flag when the task exits.
    3. Kill (SIGTERM) the exact tracked spooler PID only when force=True or Stop is pressed
       again FORCE_KILL_GRACE seconds after the first press - never for NEVER_KILL_SIGNALS.

    Returns dict(result, removed_files, killed_pids, cancelled_rows, mode).
    """
    now = time.time() if now is None else now
    removed = remove_queued_spool_files(task_signal, task_id)
    first_press = _mark_cancel_requested(task_signal, now)
    escalate = force or (now - first_press) >= FORCE_KILL_GRACE

    killed = []
    if escalate and task_signal not in NEVER_KILL_SIGNALS:
        known = spooler_pids()
        for entry in get_running(task_signal):
            if task_id and str(entry.get("task_id") or "") != str(task_id):
                continue
            pid = entry.get("pid")
            stale = not pid_alive(pid)
            if is_safe_to_kill(pid, known):
                try:
                    kill(int(pid), os_signal.SIGTERM)
                    killed.append(int(pid))
                except ProcessLookupError:
                    stale = True
                except Exception as e:
                    log.warning("task_tracker: could not stop pid %s: %s", pid, e)
            # Drop the registration when the process is gone (killed or crashed/harakiri)
            if entry.get("field") and (stale or int(pid or 0) in killed):
                forget_running(task_signal, entry["field"])

    T = db_tasks.Tasks
    cond = (T.signal == task_signal) & (T.status == True)
    if task_id:
        cond = cond & (T.task_id == str(task_id))
    with database.connection_context():
        if killed:
            rows = T.update(action="None", status=False).where(cond).execute()
        else:
            rows = T.update(action="cancel").where(cond).execute()
    if killed:
        try:
            _redis().delete(CANCEL_KEY.format(task_signal))
        except Exception:
            pass
    if not rows and not killed:
        # Nothing running: do not leave a cancel request behind for the next run.
        try:
            _redis().delete(CANCEL_KEY.format(task_signal))
        except Exception:
            pass

    ok = bool(removed or killed or rows)
    return {
        "result": "success" if ok else "failed",
        "removed_files": removed,
        "killed_pids": killed,
        "cancelled_rows": rows,
        "mode": "killed" if killed else ("graceful" if rows else "queued-only"),
    }
