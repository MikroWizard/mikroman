#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_user_tasks.py: Models and functions for accsessing db
# MikroWizard.com , Mikrotik router management solution
# Author: Tomi.Mickelsson@iki.fi modified by sepehr.ha@gmail.com

from peewee import *
from playhouse.pool import MaxConnectionsExceeded
from playhouse.shortcuts import model_to_dict
from psycopg2.extensions import ISOLATION_LEVEL_READ_COMMITTED

from flask import abort
import config
import os
import time

import functools
import logging
import threading
from libs.db import db_budget

try:
    import uwsgi as _uwsgi
except ImportError:
    _uwsgi = None

log = logging.getLogger("db")

SLOW_POOL_WAIT_SECONDS = 1.0
BUDGET_REFRESH_SECONDS = 600
_budget_lock = threading.Lock()
_budget_state = {"pid": None, "at": 0.0, "role": None, "size": None, "busy": False}
_last_warning = {"at": 0.0}

# Errors worth retrying: pool exhausted, connection refused/lost. Callers that must not lose
# a write (syslog) retry these instead of swallowing them.
TRANSIENT_DB_ERRORS = (OperationalError, InterfaceError, MaxConnectionsExceeded)


def _rate_limited_warning(msg, every=30.0):
    now = time.time()
    if now - _last_warning["at"] >= every:
        _last_warning["at"] = now
        log.warning(msg)


def _explicit_pool_size():
    """PYSRV_DATABASE_POOL_SIZE set in server-conf.json / env -> respected as-is."""
    try:
        if "PYSRV_DATABASE_POOL_SIZE" in config.srvconf:
            return int(config.srvconf["PYSRV_DATABASE_POOL_SIZE"])
    except Exception:
        pass
    return None


def _maybe_apply_budget(db, role=None, force=False):
    """Size this process' pool from the server limit; runs once per process (per fork) and
    every BUDGET_REFRESH_SECONDS. Never raises."""
    pid = os.getpid()
    now = time.time()
    st = _budget_state
    if not force and st["pid"] == pid and (now - st["at"]) < BUDGET_REFRESH_SECONDS and (role is None or role == st["role"]):
        return
    if not _budget_lock.acquire(blocking=False):
        return
    try:
        if st["busy"]:
            return
        st["busy"] = True
        role = db_budget.ROLE_ALIASES.get(role or "", None) or (st["role"] if st["pid"] == pid and st["role"] else db_budget.detect_role(_uwsgi))
        explicit = _explicit_pool_size()
        if explicit and explicit > 0:
            size, source = explicit, "PYSRV_DATABASE_POOL_SIZE"
        else:
            def _query(sql):
                return super(type(db), db).execute_sql(sql)
            if db.is_closed():
                # Called outside a request/connection: use a short-lived connection, never leak it.
                with db.connection_context():
                    limits = db_budget.read_server_limits(_query)
            else:
                limits = db_budget.read_server_limits(_query)
            if not limits:
                log.warning("DB pool for %s (pid %s): could not read max_connections, keeping %s",
                            role, pid, db._max_connections)
                st.update(pid=pid, at=now, role=role)
                return
            topo = db_budget.topology_from_uwsgi_opt(getattr(_uwsgi, "opt", None) if _uwsgi else None)
            topo["cron_jobs"] = max(0, int(getattr(config, "DB_CRON_JOBS", 2)))
            budget = db_budget.compute_budget(limits[0], limits[1], topo)
            size, source = budget[role], "auto (max_connections=%s, total budget %s)" % (limits[0], budget["total"])
        changed = bool(size and size != db._max_connections)
        if changed:
            db._max_connections = size
        if changed or st.get("logged") != (pid, role):
            log.info("DB pool for %s (pid %s) = %s connections [%s]", role, pid, db._max_connections, source)
            st["logged"] = (pid, role)
        st.update(pid=pid, at=now, role=role, size=size)
    except Exception as e:
        log.warning("Could not apply DB connection budget: %s", e)
    finally:
        st["busy"] = False
        _budget_lock.release()

if config.IS_SQLITE:
    # config.DATABASE_HOST is full path to sqlite file
    database = SqliteDatabase(config.DATABASE_HOST, pragmas={})
else:
    from playhouse.pool import PooledPostgresqlExtDatabase, MaxConnectionsExceeded
    from playhouse.postgres_ext import ArrayField, BinaryJSONField, BooleanField, JSONField
    # support for arrays of uuid
    import psycopg2.extras
    psycopg2.extras.register_uuid()

    class MWPooledPostgresqlExtDatabase(PooledPostgresqlExtDatabase):
        """Peewee pool with:
          * automatic per-process pool size from the server's max_connections (db_budget),
            applied on the first connection of every process (works after uWSGI forks);
          * retry with back-off when PostgreSQL itself refuses ("too many clients");
          * a warning when a thread had to wait long for a connection (early pressure signal);
          * reclaim of connections left checked out by threads that have ended. Peewee keeps a
            connection "in use" until the thread that opened it calls close(); a worker thread
            that queried and exited without closing (short-lived ThreadPoolExecutor jobs,
            notification threads) would otherwise hold that slot until the process restarts -
            with the small per-process pools of the DB budget that starves the process.
        """

        RECLAIM_EVERY_SECONDS = 60

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._conn_owner = {}
            self._last_reclaim = 0.0

        def _owner_key(self, conn):
            return self.conn_key(conn) if hasattr(self, "conn_key") else id(conn)

        def _connect(self):
            # Called with the database lock held (Database.connect).
            try:
                conn = super()._connect()
            except MaxConnectionsExceeded:
                if not self.reclaim_dead_thread_connections():
                    raise
                conn = super()._connect()
            self._conn_owner[self._owner_key(conn)] = threading.current_thread()
            return conn

        def _close(self, conn, close_conn=False):
            self._conn_owner.pop(self._owner_key(conn), None)
            return super()._close(conn, close_conn)

        def reclaim_dead_thread_connections(self):
            """Close connections checked out by threads that no longer run. Returns how many."""
            reclaimed = 0
            for key, owner in list(self._conn_owner.items()):
                if owner.is_alive():
                    continue
                self._conn_owner.pop(key, None)
                pool_conn = self._in_use.pop(key, None)
                if pool_conn is None:
                    continue
                try:
                    pool_conn.connection.close()
                except Exception:
                    pass
                reclaimed += 1
            self._last_reclaim = time.time()
            if reclaimed:
                _rate_limited_warning("Reclaimed %d DB connection(s) left open by finished threads "
                                      "(pool %s, in use %s)" % (reclaimed, self._max_connections, len(self._in_use)))
            return reclaimed

        def connect(self, reuse_if_open=False):
            t0 = time.time()
            deadline = t0 + (self._wait_timeout if self._wait_timeout and self._wait_timeout != float("inf") else 30)
            delay = 0.2
            while True:
                try:
                    ret = super().connect(reuse_if_open)
                    break
                except (OperationalError, psycopg2.OperationalError) as e:
                    msg = str(e).lower()
                    if ("too many clients" not in msg and "remaining connection slots" not in msg) \
                            or time.time() + delay > deadline:
                        raise
                    _rate_limited_warning("PostgreSQL refused a connection (%s); retrying" % str(e).strip()[:120])
                    time.sleep(delay)
                    delay = min(delay * 2, 2.0)
            if time.time() - self._last_reclaim > self.RECLAIM_EVERY_SECONDS:
                with self._lock:
                    self.reclaim_dead_thread_connections()
            waited = time.time() - t0
            if waited > SLOW_POOL_WAIT_SECONDS:
                _rate_limited_warning("Waited %.1fs for a DB connection (pool %s, in use %s) - pool pressure"
                                      % (waited, self._max_connections, len(self._in_use)))
            _maybe_apply_budget(self)
            return ret

    database = MWPooledPostgresqlExtDatabase(config.DATABASE_NAME,
        user=config.DATABASE_USER, password=config.DATABASE_PASSWORD,
        host=config.DATABASE_HOST, port=config.DATABASE_PORT,
        isolation_level=ISOLATION_LEVEL_READ_COMMITTED,
        # Initial ceiling; replaced by the auto budget (or the explicit
        # PYSRV_DATABASE_POOL_SIZE) on the first connection of each process.
        max_connections=max(getattr(config, "DATABASE_POOL_SIZE", 8), 8),
        stale_timeout=config.DB_STALE_TIMEOUT,   # Close idle connections after N seconds
        timeout=getattr(config, "DATABASE_POOL_TIMEOUT", 30),  # Wait up to 30s instead of crashing
    )

# --------------------------------------------------------------------------
# DEV_MODE Database Call Monitoring
# --------------------------------------------------------------------------
_db_stats = {
    "total": 0,
    "select": 0,
    "update": 0,
    "insert": 0,
    "delete": 0,
    "other": 0
}

def get_db_stats():
    return dict(_db_stats)

def reset_db_stats():
    for k in _db_stats:
        _db_stats[k] = 0

if os.getenv("DEV_MODE") == "true":
    _orig_execute_sql = database.execute_sql

    def _monitored_execute_sql(sql, params=None, *args, **kwargs):
        t0 = time.time()
        res = _orig_execute_sql(sql, params, *args, **kwargs)
        elapsed = time.time() - t0
        _db_stats["total"] += 1
        sql_stripped = sql.strip().upper()
        clean_sql = " ".join(sql.split())
        if sql_stripped.startswith("SELECT"):
            _db_stats["select"] += 1
        elif sql_stripped.startswith("UPDATE"):
            log.info("[DEV_MODE DB CALL] (%0.2fms) %s", elapsed * 1000, clean_sql[:140])
            _db_stats["update"] += 1
        elif sql_stripped.startswith("INSERT"):
            log.info("[DEV_MODE DB CALL] (%0.2fms) %s", elapsed * 1000, clean_sql[:140])
            _db_stats["insert"] += 1
        elif sql_stripped.startswith("DELETE"):
            log.info("[DEV_MODE DB CALL] (%0.2fms) %s", elapsed * 1000, clean_sql[:140])
            _db_stats["delete"] += 1
        else:
            _db_stats["other"] += 1
        # log.info("[DEV_MODE DB CALL] (%0.2fms) %s", elapsed * 1000, clean_sql[:140])
        return res

    database.execute_sql = _monitored_execute_sql
    log.info("[DEV_MODE] Database call monitoring enabled")


def release_db_connection(fn):
    """Decorator for jobs run by LONG-LIVED pool threads (alert dispatch, RADIUS workers):
    return the thread's pooled connection after every job. Without it each pool thread keeps
    one connection checked out forever (Peewee releases a connection only on close())."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        finally:
            try:
                database.close()
            except Exception:
                pass
    return wrapper


def tune_process_db_pool(role="worker", num_devices=None):
    """Apply the connection budget for this process' role.

    Pool size comes from PostgreSQL's real max_connections split across all uWSGI processes
    (libs/db/db_budget.py), or from PYSRV_DATABASE_POOL_SIZE when an operator set it.
    num_devices is accepted for backward compatibility; the pool does not need to grow with
    fleet size because each device holds a connection for milliseconds only.
    """
    if config.IS_SQLITE or not hasattr(database, "_max_connections"):
        return
    _maybe_apply_budget(database, role=role)


def reset_db():
    """Close all pooled connections so the next query opens fresh sockets.

    Called at the start of each uWSGI spool job to discard any connection
    inherited across a fork (which would otherwise fail with
    "could not receive data from server: Socket operation on non-socket").
    This only affects the current process's pool, never other workers/spoolers.
    """
    try:
        database.close_all()
    except AttributeError:
        try:
            database.close()
        except Exception:
            pass
    except Exception:
        pass


# --------------------------------------------------------------------------
# Base model and common methods

class BaseModel(Model):
    """Base class for all database models."""

    # exclude these fields from the serialized dict
    EXCLUDE_FIELDS = []

    def serialize(self):
        """Serialize the model into a dict."""
        d = model_to_dict(self, recurse=False, exclude=self.EXCLUDE_FIELDS)
        d["id"] = str(d["id"]) # unification: id is always a string
        return d

    class Meta:
        database = database


def get_object_or_404(model, **kwargs):
    """Retrieve a single object or abort with 404."""

    try:
        return model.get(**kwargs)
    except model.DoesNotExist:
        log.warning("NO OBJECT {} {}".format(model, kwargs))
        abort(200)

def get_object_or_none(model, **kwargs):
    """Retrieve a single object or return None."""

    try:
        return model.get(**kwargs)
    except model.DoesNotExist:
        return None


# --------------------------------------------------------------------------
# USER

class User(BaseModel):

    # Should user.id be an integer or uuid? Both have pros and cons.
    # Since user.id is sensitive data, I selected uuid here.
    if not config.IS_SQLITE:
        id = UUIDField(primary_key=True)
        id.auto_increment = True # is auto generated by server

    username = TextField()
    password = TextField()
    hash = TextField()
    first_name = TextField()
    last_name = TextField()
    role = TextField()
    email = TextField()
    adminperms = TextField()
    if not config.IS_SQLITE:
        tags = ArrayField(TextField)
    else:
        tags = TextField()

    created = DateTimeField()
    modified = DateTimeField()

    EXCLUDE_FIELDS = [password,hash] # never expose password


    def is_superuser(self):
        return self.role == "superuser"

    def full_name(self):
        return "{} {}".format(self.first_name, self.last_name or '')

    def serialize(self):
        """Serialize this object to dict/json."""

        d = super(User, self).serialize()

        # add extra data
        d["fullname"] = self.full_name()
        d["tags"] = self.tags or [] # never None
        return d

    def __str__(self):
        return "<User {}, {}, role={}>".format(self.id,
                self.username, self.role)

    class Meta:
        db_table = 'users'


def get_user(uid):
    """Return user object or throw."""
    return get_object_or_404(User, id=uid)


def get_user_by_username(username):
    """Return user object or None"""

    if not username:
        return None

    try:
        # return User.select().where(User.username == username).get()
        # case insensitive query
        if config.IS_SQLITE:
            sql = "SELECT * FROM users where username = ? LIMIT 1"
            args = username.lower()
        else:
            sql = "SELECT * FROM users where LOWER(username) = LOWER(%s) LIMIT 1"
            args = (username,)
        return list(User.raw(sql, args))[0]

    except IndexError:
        return None


def query_users(page=0, limit=1000, search=None):
    """Return list of users. Desc order"""

    page = int(page or 0)
    limit = int(limit or 1000)

    q = User.select()
    if search:
        search = "%"+search+"%"
        q = q.where(User.first_name ** search | User.last_name ** search |
                User.username ** search)
    q = q.paginate(page, limit).order_by(User.id.desc())
    return q


# --------------------------------------------------------------------------

if __name__ == '__main__':

    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)

