#!/usr/bin/python
# -*- coding: utf-8 -*-

# audit_redact_backfill.py: one-time background cleanup of secrets already stored in the
# System Log (syslogs.data) by versions <= 2.1.0. New events are masked at write time by
# libs/audit_redact.py; this only fixes old rows.
#
# Safety:
#   - runs in its own daemon thread, never blocks startup, logins or logging
#   - one process at a time (Redis lock), walks the primary key in small id ranges,
#     each range one short transaction; only rows that actually change are updated
#   - progress (last id) is kept in sysconfig, so a restart resumes where it stopped
#   - any error: log it, stop, retry later; marks itself done when finished
#   - idempotent: masked values ("***") are never masked again

import logging
import os
import threading
import time

from libs.db.db import database
from libs.db import db_sysconfig
from libs import job_control
from libs.audit_redact import redact_audit_data, SQL_CANDIDATE_REGEX

log = logging.getLogger("audit_redact_backfill")

DONE_KEY = "audit_redaction_backfill"          # sysconfig: "done" when finished
LAST_ID_KEY = "audit_redaction_last_id"        # sysconfig: last syslogs.id processed
LOCK_KEY = "mw:audit_redact:lock"
LOCK_SECONDS = 2 * 3600
RANGE = 5000                                   # ids per range (one short transaction)
PAUSE = 0.2                                    # seconds between ranges
RETRY_SECONDS = 3600                           # after an error or a busy lock

_RELEASE_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"
_state = {"t": None, "done": False, "next_try": 0.0}


def _get_last_id():
    try:
        with database.connection_context():
            return int(db_sysconfig.get_sysconfig(LAST_ID_KEY) or 0)
    except Exception:
        return 0


def _set(key, value):
    with database.connection_context():
        db_sysconfig.set_sysconfig(key, value)


def run(stop=None):
    """Process all syslogs rows once. Returns the number of rows updated."""
    with database.connection_context():
        row = database.execute_sql("SELECT max(id) FROM syslogs").fetchone()
    max_id = row[0] if row else None
    last = _get_last_id()
    updated = 0
    if max_id is not None:
        while last < max_id:
            if stop is not None and stop.is_set():
                return updated
            end = last + RANGE
            with database.connection_context():
                with database.atomic():
                    rows = database.execute_sql(
                        "SELECT id, data FROM syslogs WHERE id > %s AND id <= %s AND data ~* %s",
                        (last, end, SQL_CANDIDATE_REGEX)).fetchall()
                    for rid, data in rows:
                        new = redact_audit_data(data)
                        if new is not data:
                            database.execute_sql("UPDATE syslogs SET data = %s WHERE id = %s", (new, rid))
                            updated += 1
            last = end
            _set(LAST_ID_KEY, str(last))
            time.sleep(PAUSE)
    _set(DONE_KEY, "done")
    log.info("audit redaction backfill finished, %s rows masked", updated)
    return updated


def _worker(token):
    r = None
    try:
        r = job_control._redis()
        run()
        _state["done"] = True
    except Exception as e:
        log.warning("audit redaction backfill stopped, will retry later: %s", e)
        _state["next_try"] = time.time() + RETRY_SECONDS
    finally:
        try:
            if r is not None:
                r.eval(_RELEASE_LUA, 1, LOCK_KEY, token)
        except Exception:
            pass


def maybe_start():
    """Start the one-time cleanup in a background thread when still needed.
    Cheap to call every scheduler tick; never raises. Returns the thread or None."""
    try:
        if _state["done"] or time.time() < _state["next_try"]:
            return None
        t = _state["t"]
        if t is not None and t.is_alive():
            return None
        # check the DB / Redis at most once per RETRY_SECONDS unless a run starts
        _state["next_try"] = time.time() + RETRY_SECONDS
        with database.connection_context():
            if db_sysconfig.get_sysconfig(DONE_KEY) == "done":
                _state["done"] = True
                return None
        r = job_control._redis()
        token = "{}:{}".format(os.getpid(), time.time())
        if not r.set(LOCK_KEY, token, nx=True, ex=LOCK_SECONDS):
            return None
        t = threading.Thread(target=_worker, args=(token,), name="audit-redact-backfill", daemon=True)
        _state["t"] = t
        t.start()
        return t
    except Exception as e:
        log.warning("audit redaction backfill: cannot start: %s", e)
        return None
