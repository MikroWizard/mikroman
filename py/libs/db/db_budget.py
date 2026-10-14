#!/usr/bin/python
# -*- coding: utf-8 -*-

# db_budget.py: size each process' PostgreSQL connection pool from the server's real limit.
# MikroWizard.com , Mikrotik router management solution
#
# Every uWSGI process (web workers, spoolers, mules) has its own Peewee pool. The sum of all
# pools must stay below PostgreSQL's max_connections or the server answers
# "FATAL: sorry, too many clients already". Instead of hard-coded tiers, each process asks
# the server (SHOW max_connections) and takes its share of the budget for its role.
# Pure functions here are unit-tested; db.py applies the result on a process' first connect.

import logging
import os
import sys

log = logging.getLogger("db_budget")

SAFETY_MARGIN = 10          # connections kept free for psql, migrations, monitoring, other apps
WEB_CONNS_PER_THREAD = 2    # a web request rarely needs more than 1 (+1 for nested contexts)
OTHER_MULE_CONNS = 3        # radius / syslog / updater
SYSLOG_SHARE = 0.05         # syslog mule: extra connections from the spare budget (measured +9 % msg/s
                            # from 3 to 6, tests/loadtest/syslog_load.py); default installs keep 3
CRON_JOB_CONNS = 4          # a scheduled task (task_run.py, own process): measured < 2 in use on
                            # average while backing up 1500 devices with 40 threads
POLLER_SHARE = 0.25
FIRMWARE_SHARE = 0.15
MIN_POOL = {"web": 2, "spooler": 3, "poller": 4, "firmware": 3, "mule": 2, "cli": 4, "syslog": 3}
MAX_POOL = {"web": 8, "spooler": 40, "poller": 60, "firmware": 40, "mule": 6, "cli": 20, "syslog": 6}

DEFAULT_TOPOLOGY = {
    "web": 4, "web_threads": 1, "spoolers": 4, "pollers": 1, "firmware": 1, "other_mules": 3,
    # of the other_mules: syslog mules (they get the "syslog" pool instead of the "mule" one)
    "syslog_mules": 1,
    # scheduled tasks (cron -> task_run.py) that may run at the same time (PYSRV_DB_CRON_JOBS)
    "cron_jobs": 2,
}


def _int(v, default):
    if isinstance(v, (list, tuple)):
        v = v[-1] if v else None
    if isinstance(v, bytes):
        v = v.decode(errors="ignore")
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _list(v):
    if v is None:
        return []
    if not isinstance(v, (list, tuple)):
        v = [v]
    return [x.decode(errors="ignore") if isinstance(x, bytes) else str(x) for x in v]


def mules_from_ini(ini_spec):
    """Mule scripts declared in the uWSGI ini file/section ('path.ini:section').

    uwsgi.opt keeps only ONE value for repeated options such as `mule =`, so the real list
    has to be read from the ini file itself."""
    if not ini_spec:
        return []
    if isinstance(ini_spec, (list, tuple)):
        ini_spec = ini_spec[-1]
    if isinstance(ini_spec, bytes):
        ini_spec = ini_spec.decode(errors="ignore")
    path, _, section = str(ini_spec).partition(":")
    if not os.path.isfile(path):
        return []
    mules, current = [], None
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1].strip()
                    continue
                if (not section or current == section or (current is None and not section)) and "=" in line:
                    k, _, v = line.partition("=")
                    if k.strip() == "mule":
                        mules.append(v.split("#")[0].strip())
    except OSError:
        return []
    return mules


def _mule_list(opt):
    if not opt:
        return []
    get = lambda k: opt.get(k, opt.get(k.encode()))  # noqa: E731
    from_ini = mules_from_ini(get("ini"))
    from_opt = _list(get("mule"))
    return from_ini if len(from_ini) >= len(from_opt) else from_opt


def topology_from_uwsgi_opt(opt):
    """Process layout from uwsgi.opt (dict of bytes / lists). Falls back to defaults."""
    if not opt:
        return dict(DEFAULT_TOPOLOGY)
    mules = _mule_list(opt)
    get = lambda k: opt.get(k, opt.get(k.encode()))  # noqa: E731
    topo = {
        "web": max(1, _int(get("processes"), DEFAULT_TOPOLOGY["web"])),
        "web_threads": max(1, _int(get("threads"), 1)),
        "spoolers": max(0, _int(get("spooler-processes"), DEFAULT_TOPOLOGY["spoolers"])),
        "pollers": sum(1 for m in mules if "data_grabber" in m) if mules else 1,
        "firmware": sum(1 for m in mules if "firmware" in m) if mules else 1,
    }
    topo["other_mules"] = (len(mules) - topo["pollers"] - topo["firmware"]) if mules else DEFAULT_TOPOLOGY["other_mules"]
    topo["syslog_mules"] = sum(1 for m in mules if "syslog" in m) if mules else DEFAULT_TOPOLOGY["syslog_mules"]
    # A poller / firmware mule must always have a share, even if the layout was unreadable.
    topo["pollers"] = max(1, topo["pollers"])
    topo["firmware"] = max(1, topo["firmware"])
    return topo


def _clamp(v, role):
    return int(max(MIN_POOL[role], min(MAX_POOL[role], v)))


def compute_budget(max_connections, reserved=3, topology=None):
    """Per-process pool size for every role so that the sum stays under the server limit.
    'cli' is the pool of a scheduled task process (task_run.py); topology['cron_jobs'] of them
    are counted in the total.

    Returns dict(web, spooler, poller, firmware, mule, syslog, cli, total, usable).
    The syslog mule(s) are part of other_mules; each gets the "syslog" pool: the "mule" pool plus a
    share of the spare budget (SYSLOG_SHARE), so a default server (max_connections=100) keeps 3.
    """
    topo = dict(DEFAULT_TOPOLOGY)
    topo.update(topology or {})
    usable = max(10, int(max_connections) - int(reserved or 0) - SAFETY_MARGIN)

    web = _clamp(topo["web_threads"] * WEB_CONNS_PER_THREAD, "web")
    mule = _clamp(OTHER_MULE_CONNS, "mule")
    cli = _clamp(CRON_JOB_CONNS, "cli")
    cron = max(0, int(topo.get("cron_jobs") or 0))
    fixed = web * topo["web"] + mule * topo["other_mules"] + cli * cron
    remaining = max(0, usable - fixed)
    syslog_mules = max(0, min(int(topo.get("syslog_mules") or 0), topo["other_mules"]))
    syslog = max(mule, _clamp(remaining * SYSLOG_SHARE, "syslog")) if syslog_mules else 0
    remaining = max(0, remaining - (syslog - mule) * syslog_mules)
    extra = (syslog - mule) * syslog_mules if syslog_mules else 0

    poller = _clamp(remaining * POLLER_SHARE / max(1, topo["pollers"]), "poller") if topo["pollers"] else 0
    firmware = _clamp(remaining * FIRMWARE_SHARE / max(1, topo["firmware"]), "firmware") if topo["firmware"] else 0
    left = remaining - poller * topo["pollers"] - firmware * topo["firmware"]
    spooler = _clamp(left / max(1, topo["spoolers"]), "spooler") if topo["spoolers"] else 0

    total = (web * topo["web"] + mule * topo["other_mules"] + extra + poller * topo["pollers"]
             + firmware * topo["firmware"] + spooler * topo["spoolers"] + cli * cron)
    # Minimums can overshoot on very small servers: scale the big roles down to fit.
    if total > usable:
        over = total - usable
        for role, count in (("spooler", topo["spoolers"]), ("poller", topo["pollers"]), ("firmware", topo["firmware"])):
            if over <= 0 or not count:
                continue
            cur = {"spooler": spooler, "poller": poller, "firmware": firmware}[role]
            cut = min(cur - MIN_POOL[role], -(-over // count))
            if cut > 0:
                if role == "spooler":
                    spooler -= cut
                elif role == "poller":
                    poller -= cut
                else:
                    firmware -= cut
                over -= cut * count
        total = (web * topo["web"] + mule * topo["other_mules"] + extra + poller * topo["pollers"]
                 + firmware * topo["firmware"] + spooler * topo["spoolers"] + cli * cron)
    return {"web": web, "spooler": spooler, "poller": poller, "firmware": firmware,
            "mule": mule, "syslog": syslog or mule, "cli": cli, "total": total, "usable": usable}


def detect_role(uwsgi_mod):
    """Role of the current process: web, spooler, poller, firmware, mule or cli."""
    if uwsgi_mod is None:
        return "cli"
    try:
        fn = getattr(uwsgi_mod, "i_am_the_spooler", None)
        if callable(fn) and fn():
            return "spooler"
    except Exception:
        pass
    try:
        mid = getattr(uwsgi_mod, "mule_id", None)
        mid = mid() if callable(mid) else int(mid or 0)
    except Exception:
        mid = 0
    if mid and mid > 0:
        mules = _mule_list(getattr(uwsgi_mod, "opt", {}) or {})
        script = mules[mid - 1] if 0 < mid <= len(mules) else ""
        if not script:
            main = sys.modules.get("__main__")
            script = getattr(main, "__file__", "") or ""
        if "data_grabber" in script:
            return "poller"
        if "firmware" in script:
            return "firmware"
        if "syslog" in script:
            return "syslog"
        return "mule"
    return "web"


ROLE_ALIASES = {"bgtasks": "spooler", "worker": "spooler", "poller": "poller",
                "firmware": "firmware", "web": "web", "spooler": "spooler", "mule": "mule", "cli": "cli",
                "syslog": "syslog"}


def read_server_limits(execute_sql):
    """(max_connections, superuser_reserved_connections) from the server, or None on error.
    execute_sql: callable(sql) -> cursor (database.execute_sql)."""
    try:
        max_conn = int(execute_sql("SHOW max_connections").fetchone()[0])
    except Exception as e:
        log.warning("db_budget: could not read max_connections: %s", e)
        return None
    try:
        reserved = int(execute_sql("SHOW superuser_reserved_connections").fetchone()[0])
    except Exception:
        reserved = 3
    return max_conn, reserved
