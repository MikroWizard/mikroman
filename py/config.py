#!/usr/bin/python
# -*- coding: utf-8 -*-

# config.py: configuration data of this app
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi

import json
import os
import time

from urllib.parse import quote
import redis

# first load config from a json file,
srvconf = json.load(open(os.environ["PYSRV_CONFIG_PATH"]))

# then override with env variables
for k, v in os.environ.items():
    if k.startswith("PYSRV_"):
        print("env override ", k)
        srvconf[k] = v

# grand switch to production!
IS_PRODUCTION = bool(srvconf["PYSRV_IS_PRODUCTION"] or False)

# local dev flag
IS_LOCAL_DEV = os.environ.get("FLASK_ENV") == "development" and not IS_PRODUCTION
# IS_LOCAL_DEV = False

print(
    "\nCONFIG: prod={},localdev={} ({})\n".format(
        IS_PRODUCTION, IS_LOCAL_DEV, srvconf["name"]
    )
)

# database config
DATABASE_HOST = srvconf["PYSRV_DATABASE_HOST"]
DATABASE_PORT = srvconf["PYSRV_DATABASE_PORT"]
DATABASE_NAME = srvconf["PYSRV_DATABASE_NAME"]
DATABASE_USER = srvconf["PYSRV_DATABASE_USER"]
DATABASE_PASSWORD = srvconf["PYSRV_DATABASE_PASSWORD"]
# Database pool size per process. Leave UNSET: each process then sizes its pool from the
# server's real max_connections (libs/db/db_budget.py). Setting it forces that size everywhere.
DATABASE_POOL_SIZE = int(srvconf.get("PYSRV_DATABASE_POOL_SIZE", 20))
# Database pool wait timeout in seconds when all connections are checked out.
DATABASE_POOL_TIMEOUT = int(srvconf.get("PYSRV_DATABASE_POOL_TIMEOUT", 30))
# Scheduled tasks (cron -> task_run.py, one process each) that may run at the same time.
# Each gets a DB pool of 4; they are counted in the connection budget of every process.
DB_CRON_JOBS = int(srvconf.get("PYSRV_DB_CRON_JOBS", 2))
# Max concurrent threads for background task executors.
MAX_CONCURRENT_THREADS = int(srvconf.get("PYSRV_MAX_CONCURRENT_THREADS", 10))
# Parallel router sessions of one backup / snippet / sequence / execution job.
# 0 = auto by job size (<=100 devices: MAX_CONCURRENT_THREADS, <=500: 25, more: 40).
JOB_CONCURRENCY = int(srvconf.get("PYSRV_JOB_CONCURRENCY", 0))
# Seconds a spooler job may start new devices. 0 = auto: spooler-harakiri - 300 s
# (devices already running get the rest), so a big job returns partial results
# instead of being killed by harakiri. Scheduled tasks have no limit.
JOB_DEADLINE = int(srvconf.get("PYSRV_JOB_DEADLINE", 0))
# MikroTik commands over the non-interactive SSH exec channel (one request, no prompt
# handling, ~0.1 s instead of seconds per device): 'template' = only templates flagged
# connection.is_non_interactive, 'all' = every MikroTik device, 'off' = never.
MIKROTIK_EXEC = str(srvconf.get("PYSRV_MIKROTIK_EXEC", "template"))
# Retention (libs/retention.py, run once a day by the firmware mule). 0 = keep forever.
# Days of command_execution_log rows (every backup / snippet / command run).
RETENTION_EXEC_LOG_DAYS = int(srvconf.get("PYSRV_RETENTION_EXEC_LOG_DAYS", 180))
# Days of task_results rows (snippet, scan, bulk-add results).
RETENTION_TASK_RESULTS_DAYS = int(srvconf.get("PYSRV_RETENTION_TASK_RESULTS_DAYS", 90))
# Days of failed sequence history (successful runs are already pruned per device).
RETENTION_SEQUENCE_HISTORY_DAYS = int(srvconf.get("PYSRV_RETENTION_SEQUENCE_HISTORY_DAYS", 90))
# Config versions and backup rows older than these days are removed, except the newest
# RETENTION_VERSIONS_KEEP of every device, which are always kept.
RETENTION_VERSIONS_DAYS = int(srvconf.get("PYSRV_RETENTION_VERSIONS_DAYS", 365))
RETENTION_VERSIONS_KEEP = int(srvconf.get("PYSRV_RETENTION_VERSIONS_KEEP", 30))
# Remove stored config / output files no row references any more (1 = on, 0 = off).
RETENTION_BLOB_GC = int(srvconf.get("PYSRV_RETENTION_BLOB_GC", 1))
# Local hour (0-23) the daily cleanup starts.
RETENTION_HOUR = int(srvconf.get("PYSRV_RETENTION_HOUR", 3))
# Seconds before an idle DB connection is closed. Min 60, recommend 180-600.
DB_STALE_TIMEOUT = int(srvconf.get("PYSRV_DB_STALE_TIMEOUT", 300))
# Socket connect timeout for IP scanning. LAN=0.2, WAN=0.5, VPN/slow=1.0.
SOCKET_SCAN_TIMEOUT = float(srvconf.get("PYSRV_SOCKET_SCAN_TIMEOUT", 0.2))
# Max concurrent RouterOS API connections for data grabber mule.
DATAGRABBER_CONCURRENCY = int(srvconf.get("PYSRV_DATAGRABBER_CONCURRENCY", 25))
# Sharding configuration for multiple data grabber mules (e.g. "2,6" or "[2,6]")
DATAGRABBER_MULES = srvconf.get("PYSRV_DATAGRABBER_MULES", "")
# Hard ceiling (seconds) for one poll cycle; hung device threads are abandoned after this.
DATAGRABBER_CYCLE_DEADLINE = int(srvconf.get("PYSRV_DATAGRABBER_CYCLE_DEADLINE", 240))
# Seconds the poller reuses a device's resolved API credentials (0 = resolve every poll).
CREDENTIAL_CACHE_SECONDS = int(srvconf.get("PYSRV_CREDENTIAL_CACHE_SECONDS", 300))
# Seconds between re-reads of rarely-changing device info (routerboard, identity, wireless
# mode, syslog/RADIUS enforcement). Uptime/resources/traffic are read every poll. 0 = every poll.
STATIC_POLL_SECONDS = int(srvconf.get("PYSRV_STATIC_POLL_SECONDS", 300))
# Max concurrent firmware update threads. Firmware uploads are heavy per device.
FIRMWARE_CONCURRENCY = int(srvconf.get("PYSRV_FIRMWARE_CONCURRENCY", 40))
# Routers downloading a package from this server at the same time (/tool/fetch is served by
# the uWSGI web workers: keep at least one worker free for the UI).
FIRMWARE_MAX_TRANSFERS = int(srvconf.get("PYSRV_FIRMWARE_MAX_TRANSFERS", 3))
# Seconds a rebooted router may take to come back before the update is reported as failed.
FIRMWARE_REBOOT_TIMEOUT = int(srvconf.get("PYSRV_FIRMWARE_REBOOT_TIMEOUT", 900))
# Seconds a queued firmware request waits for an unreachable router before it is dropped.
FIRMWARE_QUEUE_MAX_AGE = int(srvconf.get("PYSRV_FIRMWARE_QUEUE_MAX_AGE", 24 * 3600))
CRYPT_KEY = srvconf["PYSRV_CRYPT_KEY"]
# Key Encryption Key for PAM envelope encryption (Task 5).
# Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add as PYSRV_KEK in /opt/mikrowizard/server-conf.json.
# The app starts normally without it; only credential encryption/decryption will fail.
KEK = srvconf.get("PYSRV_KEK", "")
TERMINAL_GATEWAY_URL = srvconf.get("terminal_gateway_url") or srvconf.get("PYSRV_TERMINAL_GATEWAY_URL") or "http://127.0.0.1:8201"
# Shared bearer secret for backend -> terminal gateway API auth (set by gateway install.sh)
TERMINAL_GATEWAY_TOKEN = srvconf.get("terminal_gateway_token", "")
BACKUP_DIR = srvconf["PYSRV_BACKUP_FOLDER"]
FIRM_DIR = srvconf["PYSRV_FIRM_FOLDER"]

try:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(FIRM_DIR, exist_ok=True)
except Exception:
    pass
IS_SQLITE = DATABASE_HOST.startswith("/")

# Flask + session config
# http://flask.pocoo.org/docs/1.0/config/
# https://pythonhosted.org/Flask-Session/
redishost = srvconf.get("PYSRV_REDIS_HOST", "127.0.0.1:6379")
redispassword = srvconf.get("PYSRV_REDIS_PASSWORD", "")

if redispassword:
    redis_url = "redis://:{}@{}/0".format(quote(str(redispassword)), redishost)
else:
    redis_url = "redis://{}".format(redishost)

flask_config = dict(
    # app config
    TESTING=IS_LOCAL_DEV,
    SECRET_KEY=None,  # we have server-side sessions
    # session config - hardcoded to Redis
    SESSION_TYPE="redis",
    SESSION_REDIS=redis.from_url(redis_url),
    SESSION_COOKIE_NAME="Session-Id",
    SESSION_COOKIE_SECURE=srvconf["PYSRV_COOKIE_HTTPS_ONLY"]
    if not IS_LOCAL_DEV
    else False,  # require https?
    SESSION_COOKIE_HTTPONLY=True,  # don't allow JS cookie access
    SESSION_KEY_PREFIX="mikrowizard::",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,  # 1 month
    SESSION_COOKIE_DOMAIN=srvconf["PYSRV_DOMAIN_NAME"] or None
    if not IS_LOCAL_DEV
    else None,
)

# dump sql statements in log file?
PYSRV_LOG_SQL = srvconf.get("PYSRV_LOG_SQL")

# allow API access to this domain
CORS_ALLOW_ORIGIN = srvconf.get("PYSRV_CORS_ALLOW_ORIGIN", "*")

START_TIME = int(time.time())


def started_ago(as_string=False):
    """Returns how many seconds ago the server was started. Or as a string."""

    ago = int(time.time()) - START_TIME
    if as_string:
        return "{}d {:02d}:{:02d}:{:02d}".format(
            int(ago / 60 / 60 / 24),
            int(ago / 60 / 60) % 24,
            int(ago / 60) % 60,
            ago % 60,
        )
    else:
        return ago
