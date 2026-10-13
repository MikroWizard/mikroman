#!/usr/bin/python
# -*- coding: utf-8 -*-

# job_control.py: shared machinery of the device jobs (backups, snippets, sequences,
# multi-brand executions) run by spoolers and scheduled tasks.
# MikroWizard.com , Mikrotik router management solution
#
# Job lease     mw:job:lease:<signal>:<task_id|_>
#               One run per job type (or per run id for multi-brand executions). Short TTL,
#               refreshed by one heartbeat thread per process, so a spooler killed by
#               harakiri / OOM / restart frees its job type within LEASE_TTL. The tasks
#               row flag (status) is only a display of the lease: a flag without a lease is
#               stale and is reset (reconcile_stale_flags) - nothing stays "running" forever.
# Device lock   mw:devlock:<device_id>
#               One job at a time works on a router (manual, scheduled, sequence). The
#               firmware engine (fw_state lease) and jobs never work on the same router.
# run_devices   bounded thread pool: no new device starts after the deadline or a stop
#               request, busy devices are skipped, every device gets exactly one result,
#               no DB connection is held by the coordinating thread.

import datetime
import hashlib
import json
import logging
import os
import pickle
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from cryptography.fernet import Fernet

import config
from libs.red import RedisDB
from libs.db import db_tasks
from libs.db.db import database

try:
    import uwsgi
except ImportError:
    uwsgi = None

log = logging.getLogger("job_control")

LEASE_KEY = "mw:job:lease:{}:{}"
DEVLOCK_KEY = "mw:devlock:{}"
FW_LEASE_KEY = "mw:fw:lease:{}"          # libs/fw_state.LEASE_KEY
FW_RECORD_KEY = "mw:fw:rec:{}"           # libs/fw_state.RECORD_KEY
LEASE_TTL = 120                          # seconds without heartbeat before a lease is free
HEARTBEAT_INTERVAL = 30
MANAGED_SIGNALS = (120, 160, 175, 185)   # job types whose tasks.status flag follows the lease
REQUEUE_DELAY = 20                       # seconds between attempts of a queued (busy) job
QUEUE_MAX_AGE = 6 * 3600                 # a queued job that never got its turn is dropped
SPOOL_ARGS_LIMIT = 60000                 # uWSGI spool requests are limited to 64 KB in total
DEVICE_TIME_RESERVE = 300                # seconds left after the deadline for devices in flight
MULTI_BRAND_ROWS_KEEP_DAYS = 7

_held = {}                               # redis key -> token (held by this process)
_held_lock = threading.Lock()
_hb_thread = None
_hb_pid = None

_RELEASE_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end
"""
_REFRESH_LUA = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end
"""


def _redis():
    return RedisDB({}).r


def _token():
    return "{}:{}:{}:{}".format(socket.gethostname(), os.getpid(), threading.get_ident(), uuid.uuid4().hex[:8])


# ---------------------------------------------------------------------------
# Held keys + heartbeat (one thread per process)
# ---------------------------------------------------------------------------

def _ensure_heartbeat():
    global _hb_thread, _hb_pid
    if _hb_thread is not None and _hb_thread.is_alive() and _hb_pid == os.getpid():
        return
    with _held_lock:
        if _hb_thread is not None and _hb_thread.is_alive() and _hb_pid == os.getpid():
            return
        if _hb_pid != os.getpid():
            _held.clear()                # forked child: the parent's keys are not ours
        _hb_pid = os.getpid()
        _hb_thread = threading.Thread(target=_heartbeat_loop, name="job-lease-heartbeat", daemon=True)
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
    except Exception as e:
        log.warning("job lease heartbeat: redis unavailable: %s", e)
        return 0
    for key, token in items:
        try:
            if r.eval(_REFRESH_LUA, 1, key, token, LEASE_TTL):
                refreshed += 1
            else:
                log.error("job lease %s was lost", key)
                with _held_lock:
                    if _held.get(key) == token:
                        _held.pop(key, None)
        except Exception as e:
            log.warning("could not refresh %s: %s", key, e)
    return refreshed


def _take(key):
    """SET NX with heartbeat. Returns the token, None when held by someone else, or False
    when Redis is not reachable."""
    token = _token()
    try:
        ok = _redis().set(key, token, nx=True, ex=LEASE_TTL)
    except Exception as e:
        log.warning("could not take %s (redis): %s", key, e)
        return False
    if not ok:
        return None
    _ensure_heartbeat()                  # may reset _held after a fork: before registering
    with _held_lock:
        _held[key] = token
    return token


def _give_back(key, token):
    if not token:
        return
    with _held_lock:
        if _held.get(key) == token:
            _held.pop(key, None)
    try:
        _redis().eval(_RELEASE_LUA, 1, key, token)
    except Exception as e:
        log.warning("could not release %s: %s", key, e)


# ---------------------------------------------------------------------------
# Job lease + tasks row flag
# ---------------------------------------------------------------------------

def _lease_key(signal, task_id=None):
    return LEASE_KEY.format(int(signal), task_id or "_")


def _task_cond(signal, task_id=None):
    T = db_tasks.Tasks
    cond = (T.signal == int(signal))
    if task_id:
        cond = cond & (T.task_id == str(task_id))
    return cond


class JobClaim(object):
    def __init__(self, signal, task_id, token, redis_ok):
        self.signal = signal
        self.task_id = task_id
        self.token = token
        self.redis_ok = redis_ok


def claim_job(signal, task_id=None):
    """Start a run of a job type. Returns a JobClaim, or None when another run holds it.

    The Redis lease decides; the tasks row (status=1, starttime) is updated afterwards for
    the UI. Without Redis the row itself is claimed atomically (status 0 -> 1)."""
    key = _lease_key(signal, task_id)
    token = _take(key)
    if token is None:
        return None
    T = db_tasks.Tasks
    now = _now()
    try:
        with database.connection_context():
            if token is False:
                rows = (T.update(status=True, starttime=now, action="None")
                        .where(_task_cond(signal, task_id) & (T.status == False)).execute())  # noqa: E712
                if not rows:
                    return None
                return JobClaim(signal, task_id, None, False)
            T.update(status=True, starttime=now, action="None").where(_task_cond(signal, task_id)).execute()
    except Exception as e:
        # never keep a lease nobody will release (the heartbeat would keep it alive forever)
        log.error("claim of job %s/%s failed (database): %s - the request is queued again", signal, task_id, e)
        if token:
            _give_back(key, token)
        return None
    return JobClaim(signal, task_id, token, True)


def release_job(claim):
    if claim is None:
        return
    T = db_tasks.Tasks
    try:
        fields = {"status": False, "endtime": _now()}
        if claim.task_id:
            fields["action"] = "done"            # per-run row (multi-brand): this run is over
        with database.connection_context():
            T.update(**fields).where(_task_cond(claim.signal, claim.task_id)).execute()
    except Exception as e:
        log.error("could not reset task flag %s/%s: %s", claim.signal, claim.task_id, e)
    if claim.redis_ok:
        _give_back(_lease_key(claim.signal, claim.task_id), claim.token)


def job_running(signal, task_id=None):
    """True while a run of this job type holds the lease (or, without Redis, while the row
    says so)."""
    try:
        return bool(_redis().exists(_lease_key(signal, task_id)))
    except Exception:
        try:
            with database.connection_context():
                T = db_tasks.Tasks
                return T.select(T.id).where(_task_cond(signal, task_id) & (T.status == True)).exists()  # noqa: E712
        except Exception:
            return False


def reconcile_stale_flags(signals=MANAGED_SIGNALS):
    """Reset tasks rows that say 'running' while no process holds their lease (the run was
    killed). Returns the number of rows reset. Never touches rows when Redis is down."""
    T = db_tasks.Tasks
    reset = 0
    try:
        r = _redis()
        with database.connection_context():
            rows = list(T.select(T.id, T.signal, T.task_id).where(
                (T.signal.in_(list(signals))) & (T.status == True)))  # noqa: E712
            for row in rows:
                if r.exists(_lease_key(row.signal, row.task_id)) or (
                        row.task_id and r.exists(_lease_key(row.signal, None))):
                    continue
                fields = {"status": False, "endtime": _now()}
                if row.task_id:
                    fields["action"] = "done"
                if T.update(**fields).where(T.id == row.id).execute():
                    reset += 1
                    log.warning("job flag of signal %s (task %s) was left running by a stopped process - reset",
                                row.signal, row.task_id or "-")
    except Exception as e:
        log.warning("reconcile_stale_flags: %s", e)
    return reset


def ensure_task_row(signal, name, task_id=None):
    """The tasks row of a job type must exist for the UI and the stop button."""
    T = db_tasks.Tasks
    with database.connection_context():
        if T.select(T.id).where(_task_cond(signal, task_id)).exists():
            return
        now = _now()
        try:
            T.create(signal=int(signal), task_id=task_id, starttime=now, endtime=now, status=False,
                     action="None", name=name)
        except Exception:
            pass                         # created meanwhile by another process


def prune_run_rows(signal=185, keep_days=MULTI_BRAND_ROWS_KEEP_DAYS):
    """Multi-brand executions create one tasks row per run: delete finished old ones."""
    T = db_tasks.Tasks
    try:
        cutoff = _now() - _days(keep_days)
        with database.connection_context():
            return T.delete().where((T.signal == int(signal)) & (T.status == False) &  # noqa: E712
                                    (T.task_id.is_null(False)) & (T.endtime < cutoff)).execute()
    except Exception as e:
        log.warning("prune_run_rows: %s", e)
        return 0


def _now():
    return datetime.datetime.now()


def _days(n):
    return datetime.timedelta(days=n)


# ---------------------------------------------------------------------------
# Queue instead of drop
# ---------------------------------------------------------------------------

QUEUE_KEY = "mw:jobq:{}:{}"
_QUEUE_META = ("_queued_at", "_qid", "at")


def _request_hash(fn_name, kwargs):
    body = {k: v for k, v in kwargs.items() if k not in _QUEUE_META}
    try:
        raw = json.dumps(body, sort_keys=True, default=str)
    except Exception:
        raw = repr(sorted(body.items(), key=lambda kv: kv[0]))
    return hashlib.sha1((fn_name + raw).encode()).hexdigest()


def requeue(spool_fn, kwargs, delay=REQUEUE_DELAY, what="job"):
    """The job type is busy: run this request later instead of dropping it. Re-spools the
    same function with the same arguments and a start time (uWSGI 'at').

    An identical request that is already waiting is not queued twice (ten clicks on
    'backup all' are one backup). The waiting request is identified by its spool file: when
    that file is gone (Stop removed it, spool directory wiped) the next identical request
    is queued normally. Returns True when queued, False when dropped (duplicate or waited
    longer than QUEUE_MAX_AGE)."""
    kw = dict(kwargs)
    kw.pop("at", None)
    fn_name = getattr(spool_fn, "__name__", None) or getattr(getattr(spool_fn, "f", None), "__name__", "job")
    first = float(kw.get("_queued_at", 0) or 0) or time.time()
    qkey = QUEUE_KEY.format(fn_name, _request_hash(fn_name, kw))
    qid = kw.get("_qid") or uuid.uuid4().hex
    r = None
    try:
        r = _redis()
        if not r.set(qkey, qid + "|", nx=True, ex=120):
            holder = r.get(qkey)
            holder = holder.decode() if isinstance(holder, bytes) else (holder or "")
            holder_qid, _, holder_file = holder.partition("|")
            if holder_qid != qid:
                if not holder_file or os.path.exists(holder_file):
                    log.info("%s request is already queued - duplicate dropped", what)
                    return False
                log.info("queued %s request %s no longer exists - replaced", what, holder_qid)
    except Exception as e:
        log.warning("requeue: redis unavailable (%s) - queued without duplicate check", e)
        r = None
    if time.time() - first > QUEUE_MAX_AGE:
        log.error("%s request waited more than %d h for the running %s to finish - dropped",
                  what, QUEUE_MAX_AGE // 3600, what)
        dequeued(fn_name, kw)
        return False
    kw["_queued_at"] = first
    kw["_qid"] = qid
    kw["at"] = str(int(time.time() + delay))
    spool_file = spool_fn(**kw)
    if r is not None:
        if isinstance(spool_file, bytes):
            spool_file = spool_file.decode(errors="ignore")
        try:
            r.set(qkey, "{}|{}".format(qid, spool_file or ""), ex=QUEUE_MAX_AGE + 3600)
        except Exception:
            pass
    return True


def dequeued(fn_name, kwargs):
    """A queued request got its turn (or was dropped): identical requests may queue again."""
    if not kwargs.get("_qid"):
        return
    try:
        r = _redis()
        qkey = QUEUE_KEY.format(fn_name, _request_hash(fn_name, kwargs))
        holder = r.get(qkey)
        holder = holder.decode() if isinstance(holder, bytes) else (holder or "")
        if holder.partition("|")[0] == kwargs["_qid"]:
            r.delete(qkey)
    except Exception:
        pass


PAYLOAD_KEY = "mw:jobpayload:{}"
PAYLOAD_TTL = 7 * 24 * 3600


def stash_payload(obj, ttl=PAYLOAD_TTL):
    """Keep a large / secret job argument (e.g. bulk-add device list with passwords) out of
    the spool file: stored encrypted in Redis, the job gets the returned id."""
    pid = uuid.uuid4().hex
    blob = Fernet(config.CRYPT_KEY).encrypt(json.dumps(obj).encode())
    _redis().set(PAYLOAD_KEY.format(pid), blob, ex=int(ttl))
    return pid


def load_payload(pid):
    raw = _redis().get(PAYLOAD_KEY.format(pid))
    if raw is None:
        return None
    return json.loads(Fernet(config.CRYPT_KEY).decrypt(raw if isinstance(raw, bytes) else raw.encode()).decode())


def drop_payload(pid):
    try:
        _redis().delete(PAYLOAD_KEY.format(pid))
    except Exception:
        pass


def check_spool_size(kwargs):
    """Raise ValueError when the arguments would not fit a spool request (64 KB)."""
    size = len(pickle.dumps(kwargs))
    if size > SPOOL_ARGS_LIMIT:
        raise ValueError("request too large for the background queue ({} bytes)".format(size))
    return size


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

def _spooler_harakiri():
    try:
        if uwsgi is not None and hasattr(uwsgi, "opt"):
            v = uwsgi.opt.get("spooler-harakiri", uwsgi.opt.get(b"spooler-harakiri"))
            if isinstance(v, (list, tuple)):
                v = v[-1]
            if isinstance(v, bytes):
                v = v.decode()
            return int(v or 0)
    except Exception:
        pass
    return 0


def job_deadline(in_spooler=True):
    """Seconds a job may start new devices for. 0 = no limit (scheduled tasks run as their
    own process, nothing kills them). Spooler jobs stop starting devices early enough for
    the devices in flight to finish before spooler-harakiri kills the process."""
    configured = int(getattr(config, "JOB_DEADLINE", 0) or 0)
    if configured > 0:
        return configured
    if not in_spooler:
        return 0
    harakiri = _spooler_harakiri()
    if harakiri <= 0:
        return 0
    return max(60, harakiri - DEVICE_TIME_RESERVE, int(harakiri * 0.5))


def job_concurrency(n_devices):
    """Parallel device sessions of one job. PYSRV_JOB_CONCURRENCY > 0 fixes it; 0 = auto by
    job size (sessions are I/O bound and hold no DB connection while talking to a router)."""
    configured = int(getattr(config, "JOB_CONCURRENCY", 0) or 0)
    if configured > 0:
        n = configured
    else:
        base = int(getattr(config, "MAX_CONCURRENT_THREADS", 10) or 10)
        if n_devices <= 100:
            n = base
        elif n_devices <= 500:
            n = max(base, 25)
        else:
            n = max(base, 40)
    return max(1, min(n, 100, max(1, int(n_devices or 1))))


# ---------------------------------------------------------------------------
# Device lock
# ---------------------------------------------------------------------------

def firmware_busy(dev_id, r=None):
    """True while the firmware engine works on the router or waits for its reboot."""
    try:
        r = r or _redis()
        if r.exists(FW_LEASE_KEY.format(dev_id)):
            return True
        raw = r.get(FW_RECORD_KEY.format(dev_id))
        if not raw:
            return False
        raw = raw.decode() if isinstance(raw, bytes) else raw
        return '"state": "rebooting"' in raw or '"state": "transferring"' in raw or \
            '"state":"rebooting"' in raw or '"state":"transferring"' in raw
    except Exception:
        return False


BUSY_JOB = "another job is working on this device"
BUSY_FIRMWARE = "firmware update in progress on this device"
DEVICE_LOCK_WAIT = 600                   # seconds a job waits for a router another job is on


def lock_device(dev_id):
    """Returns (token, reason). token None + reason: the router is busy (BUSY_JOB or
    BUSY_FIRMWARE). Without Redis the job goes on unlocked (token False) - firmware updates
    cannot run without Redis either."""
    key = DEVLOCK_KEY.format(dev_id)
    token = _take(key)
    if token is False:
        return False, None
    if token is None:
        return None, BUSY_JOB
    if firmware_busy(dev_id):
        _give_back(key, token)
        return None, BUSY_FIRMWARE
    return token, None


def unlock_device(dev_id, token):
    if token:
        _give_back(DEVLOCK_KEY.format(dev_id), token)


def locked_ids(dev_ids):
    """Subset of dev_ids a job is working on (one round trip)."""
    dev_ids = list(dev_ids)
    if not dev_ids:
        return set()
    try:
        pipe = _redis().pipeline()
        for d in dev_ids:
            pipe.exists(DEVLOCK_KEY.format(d))
        return {d for d, e in zip(dev_ids, pipe.execute()) if e}
    except Exception:
        return set()


def device_locked(dev_id):
    try:
        return bool(_redis().exists(DEVLOCK_KEY.format(dev_id)))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Device runner
# ---------------------------------------------------------------------------

SKIP_DEADLINE = "deadline"
SKIP_CANCELLED = "cancelled"
SKIP_BUSY = "busy"


def run_devices(items, worker, device_id=lambda item: item, concurrency=None, deadline=0,
                should_cancel=None, skipped=None, lock=True, started_at=None, lock_wait=None):
    """Run worker(item) for every item with at most `concurrency` in parallel.

    - no item starts after `deadline` seconds (0 = no limit) or once should_cancel() is True;
    - with lock=True each router is locked for the time of its worker. A router another job
      is working on is waited for (up to lock_wait s, never past the deadline or a stop);
      a router under a firmware update is skipped (status 'busy');
    - skipped(item, reason, message) builds the result of an item that did not run;
    - exceptions of a worker become its result through skipped(item, 'error', str(e));
    - the calling thread holds no DB connection; worker threads give theirs back.
    Returns the results in the order of items.
    """
    items = list(items)
    if not items:
        return []
    concurrency = concurrency or job_concurrency(len(items))
    started_at = started_at or time.time()
    skipped = skipped or (lambda item, reason, message: {"device_id": device_id(item), "status": reason,
                                                         "error": message})
    database.close()                     # never keep a pooled connection while waiting
    results = [None] * len(items)

    def stop_reason():
        if deadline and time.time() - started_at >= deadline:
            return SKIP_DEADLINE, "not started: job time limit reached ({} s)".format(int(deadline))
        if callable(should_cancel):
            try:
                if should_cancel():
                    return SKIP_CANCELLED, "Cancelled by user before start"
            except Exception:
                pass
        return None

    wait_limit = DEVICE_LOCK_WAIT if lock_wait is None else lock_wait

    def one(idx, item):
        token = None
        did = device_id(item)
        try:
            if lock and did is not None:
                token, busy = lock_device(did)
                waited_from = time.time()
                while token is None and busy == BUSY_JOB and time.time() - waited_from < wait_limit:
                    reason = stop_reason()
                    if reason is not None:
                        return idx, skipped(item, reason[0], reason[1])
                    time.sleep(1.0)
                    token, busy = lock_device(did)
                if token is None:
                    return idx, skipped(item, SKIP_BUSY, "skipped: " + busy)
            return idx, worker(item)
        except Exception as e:
            log.exception("job worker for device %s failed", did)
            return idx, skipped(item, "error", "Worker error: {}".format(e))
        finally:
            if token:
                unlock_device(did, token)
            try:
                database.close()
            except Exception:
                pass

    stopped = None
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(items)))) as ex:
        pending = set()
        for idx, item in enumerate(items):
            while len(pending) >= concurrency:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    i, res = f.result()
                    results[i] = res
            if stopped is None:
                stopped = stop_reason()
            if stopped is not None:
                results[idx] = skipped(item, stopped[0], stopped[1])
                continue
            pending.add(ex.submit(one, idx, item))
        for f in pending:
            i, res = f.result()
            results[i] = res
    if stopped is not None:
        n = sum(1 for r in results if isinstance(r, dict) and r.get("status") == stopped[0])
        log.warning("job stopped starting devices (%s): %d of %d not started", stopped[0], n, len(items))
    return results
