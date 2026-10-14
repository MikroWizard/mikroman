#!/usr/bin/python
# -*- coding: utf-8 -*-

# retention.py: daily cleanup of job history and stored config / output files.
# MikroWizard.com , Mikrotik router management solution
#
# Started once a day by the firmware mule (maybe_start), in a background thread so the
# firmware scheduler never waits for it. Limits come from config.RETENTION_* (0 = keep
# forever). Every DELETE runs in small batches, each in its own short DB block.
#
#   command_execution_log  rows older than RETENTION_EXEC_LOG_DAYS
#   task_results           rows older than RETENTION_TASK_RESULTS_DAYS (not the vault rotation audit)
#   pro_sequence_history   failed rows older than RETENTION_SEQUENCE_HISTORY_DAYS
#   config_versions        older than RETENTION_VERSIONS_DAYS, except the newest
#   backups                RETENTION_VERSIONS_KEEP per device (and command), always kept;
#                          also the newest configuration backup row of every device
#   blob files             versions/{raw,norm}/.. files no row references (RETENTION_BLOB_GC)
#   events                 resolved events older than RETENTION_EVENTS_DAYS (open ones are kept)
#   auth                   login history older than RETENTION_AUTH_DAYS (rows with a recording kept)
#   account                config change history older than RETENTION_ACCOUNT_DAYS
#
# Blob files are shared (content addressed): one is removed only when no config version,
# execution log or backup row references it and it was not written or reused for
# BLOB_GRACE_SECONDS (config_runner.store_blob refreshes the mtime on reuse), so a job
# that is just storing a result never loses its file.

import datetime
import logging
import os
import re
import threading
import time

import config
from libs.db.db import database
from libs import job_control

log = logging.getLogger("retention")

BATCH = 2000
BLOB_GRACE_SECONDS = 2 * 86400
TMP_GRACE_SECONDS = 86400
LOCK_KEY = "mw:retention:lock"
DAY_KEY = "mw:retention:day"
LOCK_SECONDS = 20 * 3600          # longer than any run; released when the run ends

VERSIONS_DIR = os.path.join(getattr(config, "BACKUP_DIR", "/opt/mikrowizard/backups"), "versions")
_BLOB_RE = re.compile(r"(?:^|/)((?:raw|norm)/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{64}\.txt)$")

_thread = {"t": None}
_RELEASE_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"


class Stopped(Exception):
    pass


def _interval(days):
    return "{} days".format(int(days))


def _check(stop):
    if stop is not None and stop.is_set():
        raise Stopped()


def _table_exists(name):
    with database.connection_context():
        return database.execute_sql("SELECT to_regclass(%s)", ("public." + name,)).fetchone()[0] is not None


def _delete_in_batches(table, where_sql, params, stop=None):
    """DELETE FROM table WHERE where_sql, walking the primary key in ranges of BATCH ids
    (each range one short transaction, an index range scan): the cost stays linear in the
    table size, with or without an index on the date column."""
    with database.connection_context():
        lo, hi = database.execute_sql(
            "SELECT min(id), max(id) FROM {} WHERE {}".format(table, where_sql), params).fetchone()
    if lo is None:
        return 0
    total = 0
    sql = "DELETE FROM {} WHERE id >= %s AND id < %s AND {}".format(table, where_sql)
    start = lo
    while start <= hi:
        _check(stop)
        end = start + BATCH
        with database.connection_context():
            with database.atomic():
                total += database.execute_sql(sql, (start, end) + tuple(params)).rowcount
        start = end
    return total


def _delete_ids(table, ids, stop=None, batch=None):
    total = 0
    batch = batch or BATCH
    for i in range(0, len(ids), batch):
        _check(stop)
        chunk = ids[i:i + batch]
        with database.connection_context():
            with database.atomic():
                total += database.execute_sql(
                    "DELETE FROM {} WHERE id = ANY(%s)".format(table), (chunk,)).rowcount
    return total


def prune_execution_log(days, stop=None):
    if days <= 0:
        return 0
    return _delete_in_batches("command_execution_log", "executed_at < now() - %s::interval",
                              (_interval(days),), stop)


def prune_task_results(days, stop=None):
    if days <= 0:
        return 0
    # the vault password-rotation history is an audit trail: kept
    return _delete_in_batches("task_results", "created < LOCALTIMESTAMP - %s::interval"
                              " AND task_type IS DISTINCT FROM 'Vault_rotate'", (_interval(days),), stop)


def prune_sequence_history(days, stop=None):
    """Failed sequence runs (successful ones are already pruned to the latest per device)."""
    if days <= 0 or not _table_exists("pro_sequence_history"):
        return 0
    return _delete_in_batches(
        "pro_sequence_history",
        "status IS DISTINCT FROM 'success' AND created < LOCALTIMESTAMP - %s::interval",
        (_interval(days),), stop)


def _column_exists(table, column):
    with database.connection_context():
        return database.execute_sql(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public'"
            " AND table_name = %s AND column_name = %s", (table, column)).fetchone() is not None


def prune_events(days, stop=None):
    """Resolved events (DHCP / wireless / link history, fixed alerts); open ones are kept."""
    if days <= 0:
        return 0
    return _delete_in_batches("events", "status = true AND eventtime < LOCALTIMESTAMP - %s::interval",
                              (_interval(days),), stop)


def prune_auth(days, stop=None):
    """Login history. Rows linked to a session recording (recording_path, Pro) are kept."""
    if days <= 0:
        return 0
    where = "created < LOCALTIMESTAMP - %s::interval"
    if _column_exists("auth", "recording_path"):
        where += " AND (recording_path IS NULL OR recording_path = '')"
    return _delete_in_batches("auth", where, (_interval(days),), stop)


def prune_account(days, stop=None):
    """Configuration change history."""
    if days <= 0:
        return 0
    return _delete_in_batches("account", "created < LOCALTIMESTAMP - %s::interval", (_interval(days),), stop)


def _has_index_on(table, column):
    """True when an index of `table` starts with `column`."""
    with database.connection_context():
        return database.execute_sql(
            "SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]"
            " WHERE i.indrelid = to_regclass(%s) AND a.attname = %s LIMIT 1",
            ("public." + table, column)).fetchone() is not None


def prune_config_versions(days, keep, stop=None):
    """Versions last seen before `days` ago, except the newest `keep` of every device and
    command (the current version is always the newest, so it is never removed).

    Every deleted version makes PostgreSQL clear the rows that point to it
    (config_versions.previous_version_id, command_execution_log.version_id, ON DELETE SET
    NULL). Without an index on those columns that is one full table scan per version
    (measured: 2000 versions > 2 min against 1M log rows), so this step waits for
    migration 062."""
    if days <= 0:
        return 0
    missing = [t + "." + c for t, c in (("config_versions", "previous_version_id"),
                                        ("command_execution_log", "version_id")) if not _has_index_on(t, c)]
    if missing:
        log.warning("retention: config versions are not pruned until migration 062 is run "
                    "(no index on %s)", ", ".join(missing))
        return "skipped: run migration 062"
    with database.connection_context():
        ids = [r[0] for r in database.execute_sql(
            "SELECT id FROM (SELECT id, last_seen_at, row_number() OVER ("
            "  PARTITION BY device_id, command_key ORDER BY version_num DESC) AS rn"
            "  FROM config_versions) v WHERE v.rn > %s AND v.last_seen_at < now() - %s::interval",
            (max(int(keep), 1), _interval(days))).fetchall()]
    return _delete_ids("config_versions", ids, stop, batch=500)


def _is_under(path, root):
    try:
        path, root = os.path.realpath(path), os.path.realpath(root)
    except Exception:
        return False
    return path.startswith(root.rstrip(os.sep) + os.sep)


_RAW_KEY_SQL = r"substring(b.dir from '(raw/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{64}\.txt)$')"


def _newest_config_backup(dev_id):
    """Id of the device's newest backup row that holds a configuration backup: an old-format
    file, or a raw file a show_config run stored (backup rows also hold snippet / sequence
    outputs saved with 'store in backup')."""
    with database.connection_context():
        row = database.execute_sql(
            "SELECT b.id FROM backups b WHERE b.devid = %s AND ({k} IS NULL OR EXISTS ("
            "  SELECT 1 FROM command_execution_log l WHERE l.device_id = b.devid"
            "  AND l.command_key = 'show_config' AND l.raw_storage_path = {k}))"
            " ORDER BY b.created DESC, b.id DESC LIMIT 1".format(k=_RAW_KEY_SQL), (dev_id,)).fetchone()
    return row[0] if row else None


def prune_backups(days, keep, stop=None):
    """Backup rows older than `days`, except the newest `keep` of every device and the
    device's newest configuration backup (Pro writes a config backup row only when the
    config changes, so after a year without change many newer snippet rows could otherwise
    push it out). Files of the old (pre-versioning) backup format are removed with their
    row; blob files are left to the blob cleanup (other rows may share them)."""
    if days <= 0:
        return 0, 0
    with database.connection_context():
        rows = database.execute_sql(
            "SELECT id, dir, devid FROM (SELECT id, dir, devid, created, row_number() OVER ("
            "  PARTITION BY devid ORDER BY created DESC, id DESC) AS rn FROM backups) b"
            " WHERE b.rn > %s AND b.created < LOCALTIMESTAMP - %s::interval",
            (max(int(keep), 1), _interval(days))).fetchall()
    protected = set()
    for dev_id in sorted({r[2] for r in rows if r[2] is not None}):
        _check(stop)
        newest = _newest_config_backup(dev_id)
        if newest is not None:
            protected.add(newest)
    rows = [r for r in rows if r[0] not in protected]
    removed = _delete_ids("backups", [r[0] for r in rows], stop)
    backup_dir = getattr(config, "BACKUP_DIR", "")
    files = 0
    for _, path, _ in rows:
        if not path or _BLOB_RE.search(path) or not backup_dir or not _is_under(path, backup_dir) \
                or _is_under(path, VERSIONS_DIR):
            continue
        _check(stop)
        with database.connection_context():
            still_used = database.execute_sql("SELECT 1 FROM backups WHERE dir = %s LIMIT 1", (path,)).fetchone()
        if still_used:
            continue
        try:
            os.remove(path)
            files += 1
            folder = os.path.dirname(path)
            if os.path.realpath(folder) != os.path.realpath(backup_dir):
                try:
                    os.rmdir(folder)                  # the per-day folder, when now empty
                except OSError:
                    pass
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("retention: cannot remove old backup file %s: %s", path, e)
    return removed, files


def _referenced_blobs():
    refs = set()
    queries = ("SELECT DISTINCT storage_path FROM config_versions",
               "SELECT DISTINCT storage_path FROM command_execution_log WHERE storage_path IS NOT NULL",
               "SELECT DISTINCT raw_storage_path FROM command_execution_log WHERE raw_storage_path IS NOT NULL",
               "SELECT DISTINCT dir FROM backups WHERE dir IS NOT NULL")
    for q in queries:
        with database.connection_context():
            for (path,) in database.execute_sql(q).fetchall():
                m = _BLOB_RE.search(path or "")
                if m:
                    refs.add(m.group(1))
    return refs


def gc_blobs(stop=None, now=None):
    """Remove blob files no row references. Returns (files removed, bytes freed)."""
    if not os.path.isdir(VERSIONS_DIR):
        return 0, 0
    refs = _referenced_blobs()          # a DB error raises: nothing is removed
    now = now or time.time()
    candidates = []
    for kind in ("raw", "norm"):
        top = os.path.join(VERSIONS_DIR, kind)
        for dirpath, _, names in os.walk(top):
            for name in names:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, VERSIONS_DIR).replace(os.sep, "/")
                try:
                    mtime = os.stat(path).st_mtime
                except OSError:
                    continue
                if ".tmp-" in name:
                    if now - mtime > TMP_GRACE_SECONDS:
                        candidates.append((path, True))
                    continue
                if _BLOB_RE.match(rel) and rel not in refs and now - mtime > BLOB_GRACE_SECONDS:
                    candidates.append((path, False))
    if candidates and not refs:
        log.warning("retention: no stored file is referenced by any row - blob cleanup skipped")
        return 0, 0
    removed, freed = 0, 0
    for path, is_tmp in candidates:
        _check(stop)
        try:
            st = os.stat(path)
            # reused by a job since the scan (store_blob refreshes the mtime): keep it
            if now - st.st_mtime <= (TMP_GRACE_SECONDS if is_tmp else BLOB_GRACE_SECONDS):
                continue
            os.remove(path)
            removed += 1
            freed += st.st_size
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("retention: cannot remove %s: %s", path, e)
    for kind in ("raw", "norm"):
        top = os.path.join(VERSIONS_DIR, kind)
        for dirpath, dirs, names in os.walk(top, topdown=False):
            if dirpath != top and not dirs and not names:
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass
    return removed, freed


def run_all(stop=None):
    """One full cleanup. Returns a summary dict; a step that fails is logged and the others
    still run (except blob cleanup, which needs every row cleanup to have finished)."""
    c = config
    summary = {}
    steps = (
        ("execution_log", lambda: prune_execution_log(c.RETENTION_EXEC_LOG_DAYS, stop)),
        ("task_results", lambda: prune_task_results(c.RETENTION_TASK_RESULTS_DAYS, stop)),
        ("sequence_history", lambda: prune_sequence_history(c.RETENTION_SEQUENCE_HISTORY_DAYS, stop)),
        ("config_versions", lambda: prune_config_versions(c.RETENTION_VERSIONS_DAYS, c.RETENTION_VERSIONS_KEEP, stop)),
        ("backups", lambda: prune_backups(c.RETENTION_VERSIONS_DAYS, c.RETENTION_VERSIONS_KEEP, stop)),
    )
    failed = False
    started = time.time()
    for name, fn in steps:
        try:
            summary[name] = fn()
        except Stopped:
            summary["stopped"] = True
            return summary
        except Exception as e:
            failed = True
            summary[name] = "error: {}".format(e)
            log.error("retention: %s failed: %s", name, e)
    if c.RETENTION_BLOB_GC and not failed:
        try:
            summary["blobs"] = gc_blobs(stop)
        except Stopped:
            summary["stopped"] = True
            return summary
        except Exception as e:
            summary["blobs"] = "error: {}".format(e)
            log.error("retention: blob cleanup failed: %s", e)
    # Device log tables: independent of the blob cleanup above (no stored files reference them)
    for name, fn in (("events", lambda: prune_events(c.RETENTION_EVENTS_DAYS, stop)),
                     ("auth", lambda: prune_auth(c.RETENTION_AUTH_DAYS, stop)),
                     ("account", lambda: prune_account(c.RETENTION_ACCOUNT_DAYS, stop))):
        try:
            summary[name] = fn()
        except Stopped:
            summary["stopped"] = True
            return summary
        except Exception as e:
            summary[name] = "error: {}".format(e)
            log.error("retention: %s failed: %s", name, e)
    summary["seconds"] = round(time.time() - started, 1)
    log.info("retention: %s", summary)
    return summary


def _due(now):
    return now.hour >= int(getattr(config, "RETENTION_HOUR", 3)) % 24


def _worker(token):
    r = job_control._redis()
    try:
        run_all()
    except Exception as e:
        log.error("retention run failed: %s", e)
    finally:
        try:
            r.eval(_RELEASE_LUA, 1, LOCK_KEY, token)      # only our own lock
        except Exception:
            pass


def maybe_start(now=None):
    """Start today's cleanup in a background thread when it is due and no process runs it.
    Cheap enough to call every scheduler tick. Returns the thread or None."""
    now = now or datetime.datetime.now()
    if not _due(now):
        return None
    t = _thread["t"]
    if t is not None and t.is_alive():
        return None
    today = now.strftime("%Y-%m-%d")
    try:
        r = job_control._redis()
        done = r.get(DAY_KEY)
        if done in (today, today.encode()):
            return None
        token = "{}:{}".format(os.getpid(), time.time())
        if not r.set(LOCK_KEY, token, nx=True, ex=LOCK_SECONDS):
            return None
        r.set(DAY_KEY, today, ex=3 * 86400)   # once a day, even if this run fails
    except Exception as e:
        log.warning("retention: cannot check the schedule: %s", e)
        return None
    t = threading.Thread(target=_worker, args=(token,), name="retention", daemon=True)
    _thread["t"] = t
    t.start()
    return t
