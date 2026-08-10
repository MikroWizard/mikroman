#!/usr/bin/python
# -*- coding: utf-8 -*-

# config.py: configuration data of this app
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi

import json
import os
import time

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
# Database pool size (per process). Increase for high-concurrency deployments.
DATABASE_POOL_SIZE = int(srvconf.get("PYSRV_DATABASE_POOL_SIZE", 10))
# Max concurrent threads for background task executors.
MAX_CONCURRENT_THREADS = int(srvconf.get("PYSRV_MAX_CONCURRENT_THREADS", 10))
# Seconds before an idle DB connection is closed. Min 60, recommend 180-600.
DB_STALE_TIMEOUT = int(srvconf.get("PYSRV_DB_STALE_TIMEOUT", 300))
# Socket connect timeout for IP scanning. LAN=0.2, WAN=0.5, VPN/slow=1.0.
SOCKET_SCAN_TIMEOUT = float(srvconf.get("PYSRV_SOCKET_SCAN_TIMEOUT", 0.2))
# Max concurrent RouterOS API connections for data grabber mule.
DATAGRABBER_CONCURRENCY = int(srvconf.get("PYSRV_DATAGRABBER_CONCURRENCY", 25))
# Max concurrent firmware update threads. Firmware uploads are heavy per device.
FIRMWARE_CONCURRENCY = int(srvconf.get("PYSRV_FIRMWARE_CONCURRENCY", 40))
CRYPT_KEY = srvconf["PYSRV_CRYPT_KEY"]
# Key Encryption Key for PAM envelope encryption (Task 5).
# Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add as PYSRV_KEK in /opt/mikrowizard/server-conf.json.
# The app starts normally without it; only credential encryption/decryption will fail.
KEK = srvconf.get("PYSRV_KEK", "")
TERMINAL_GATEWAY_URL = srvconf.get("PYSRV_TERMINAL_GATEWAY_URL", "http://terminal-gateway:8080")
BACKUP_DIR = srvconf["PYSRV_BACKUP_FOLDER"]
FIRM_DIR = srvconf["PYSRV_FIRM_FOLDER"]

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(FIRM_DIR, exist_ok=True)
IS_SQLITE = DATABASE_HOST.startswith("/")

# Flask + session config
# http://flask.pocoo.org/docs/1.0/config/
# https://pythonhosted.org/Flask-Session/
redishost = srvconf["PYSRV_REDIS_HOST"]

flask_config = dict(
    # app config
    TESTING=IS_LOCAL_DEV,
    SECRET_KEY=None,  # we have server-side sessions
    # session config - hardcoded to Redis
    SESSION_TYPE="redis",
    SESSION_REDIS=redis.from_url("redis://{}".format(redishost)),
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
