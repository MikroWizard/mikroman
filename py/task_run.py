import re
import os
import sys
import json
import threading
import socket
from flask import request, jsonify, g
from playhouse.shortcuts import dict_to_model, update_model_from_dict

os.environ["PYSRV_CONFIG_PATH"] = "/conf/server-conf.json"

import config
from libs import util
from libs import compat_runner
from libs.db import db_user_tasks
from libs.db.db import database
from libs.webutil import app, login_required, get_myself, buildResponse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
import logging
from cron_descriptor import get_description
import queue
import datetime
try:
    from libs import utilpro
    import task_run_pro
    ISPRO = True
except ImportError:
    task_run_pro = None
    ISPRO = False

try:
    from libs import config_runner as cfg_runner
except ImportError:
    cfg_runner = None

log = logging.getLogger("api.usertasks")

MAX_WORKERS = getattr(config, "MAX_CONCURRENT_THREADS", 10)

HEARTBEAT_INTERVAL = 300
LEASE_STALE_SECONDS = 900


# ---------------------------------------------------------------------------
# Claim helpers


def _claim_task(task_id, hostname):
    """Atomically acquire lease; returns True on success."""
    with database.connection_context():
        db = database.connection()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE user_tasks SET locked_at = NOW(), locked_by = %s "
                "WHERE id = %s "
                "  AND (locked_at IS NULL OR locked_at < NOW() - INTERVAL '%s seconds') "
                "RETURNING id",
                [hostname, task_id, LEASE_STALE_SECONDS],
            )
            return cur.fetchone() is not None


def _release_task(task_id, hostname):
    """Release lease. Never releases someone else's lease."""
    with database.connection_context():
        db = database.connection()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE user_tasks SET locked_at = NULL, locked_by = NULL "
                "WHERE id = %s AND locked_by = %s",
                [task_id, hostname],
            )


def _heartbeat(task_id, hostname, stop_event):
    """Background thread: refresh locked_at every HEARTBEAT_INTERVAL."""
    while not stop_event.wait(HEARTBEAT_INTERVAL):
        try:
            with database.connection_context():
                db = database.connection()
                with db.cursor() as cur:
                    cur.execute(
                        "UPDATE user_tasks SET locked_at = NOW() "
                        "WHERE id = %s AND locked_by = %s",
                        [task_id, hostname],
                    )
        except Exception as e:
            log.warning("lease heartbeat failed: %s", e)


# ---------------------------------------------------------------------------
# Legacy executors


def backup_devs(devices):
    num_threads = len(devices)
    q = queue.Queue()

    def thread_worker(dev, q_obj):
        with database.connection_context():
            compat_runner.backup_routers(dev, q_obj)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, dev, q): dev for dev in devices}
        for future in as_completed(futures):
            try:
                future.result(timeout=600)
            except Exception as e:
                log.error(f"Backup thread failure: {e}")

    res = []
    while not q.empty():
        qres = q.get_nowait()
        if not qres.get("state", True):
            with database.connection_context():
                util.log_alert("backup", qres.get("id", 0), "Backup failed")
        res.append(qres)
    return res


def run_snippets(devices, snippet, template_key=None, user_task_id=None, snippet_id=None, store_in_backup=False):
    num_threads = len(devices)
    q = queue.Queue()

    def thread_worker(dev, snippet_content, q_obj, tmpl_key):
        with database.connection_context():
            compat_runner.run_snippets(dev, snippet_content, q_obj, tmpl_key, user_task_id=user_task_id, snippet_id=snippet_id, store_in_backup=store_in_backup)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, dev, snippet, q, template_key): dev for dev in devices}
        for future in as_completed(futures):
            try:
                future.result(timeout=600)
            except Exception as e:
                log.error(f"Snippet thread failure: {e}")

    res = []
    while not q.empty():
        qres = q.get_nowait()
        if "result" in qres and not qres["result"]:
            with database.connection_context():
                util.log_alert("run_snippet", qres.get("id", 0), "Run Snippet failed")
        res.append(qres)
    return res


# ---------------------------------------------------------------------------
# Main dispatcher


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    taksid = sys.argv[1]
    if not taksid.isdigit():
        print("Wrong Task ID")
        exit()

    hostname = socket.gethostname()

    # Lease claim
    if not _claim_task(taksid, hostname):
        print("Task {} is already claimed by another runner — skipping".format(taksid))
        exit(0)

    heartbeat_stop = threading.Event()
    hb_thread = threading.Thread(target=_heartbeat, args=(taksid, hostname, heartbeat_stop), daemon=True)
    hb_thread.start()

    try:
        utask = db_user_tasks.UserTasks.get_utask_by_id(taksid)
        if not utask:
            log.error("No task with this id {}".format(taksid))
            exit()

        devices = db_user_tasks.get_task_devices(utask)

        if utask.task_type == "backup":
            log.error("TASK TYPE BACKUP")
            res = backup_devs(devices=devices)

        elif utask.task_type == "snippet":
            log.error("TASK TYPE SNIPPET")
            snippet = utask.snippetid.content
            if not snippet:
                log.error("no snippet")
            else:
                data = json.loads(utask.data) if utask.data else {}
                store_in_backup = bool(data.get("store_in_backup", False) or getattr(utask.snippetid, "store_in_backup", False))
                template_key = getattr(utask.snippetid, "template_command_key", None)
                snippet_id = utask.snippetid.id if utask.snippetid else None
                res = run_snippets(devices=devices, snippet=snippet, template_key=template_key, user_task_id=utask.id, snippet_id=snippet_id, store_in_backup=store_in_backup)

        elif utask.task_type == "config_backup":
            log.error("TASK TYPE CONFIG BACKUP")
            if cfg_runner is None:
                log.error("config_runner not available")
                exit()
            data = json.loads(utask.data) if utask.data else {}
            res = cfg_runner.run_bulk_job({
                "device_ids": [d.id for d in devices],
                "command_key": data.get("command_key", "show_config"),
                "user_task_id": utask.id,
                "max_workers": MAX_WORKERS,
            })

        elif utask.task_type == "command_exec":
            log.error("TASK TYPE COMMAND EXEC")
            if cfg_runner is None:
                log.error("config_runner not available")
                exit()
            data = json.loads(utask.data) if utask.data else {}
            res = cfg_runner.run_bulk_job({
                "device_ids": [d.id for d in devices],
                "command_key": data.get("command_key"),
                "custom_command": data.get("custom_command"),
                "snippet_id": data.get("snippet_id"),
                "snippet_content": data.get("snippet_content"),
                "is_config_mode": data.get("is_config_mode", False),
                "user_task_id": utask.id,
                "max_workers": MAX_WORKERS,
            })

        elif utask.task_type == "firmware":
            log.error("firmware update")
            if not ISPRO:
                exit()
            res = utilpro.run_firmware_task(utask)

        elif utask.task_type == "vault":
            log.error("vault")
            if not ISPRO:
                exit()
            res = utilpro.run_vault_task(utask)

        elif utask.task_type == "sequence":
            log.error("sequence task")
            if not ISPRO or not task_run_pro:
                exit()
            res = task_run_pro.run_sequence_task(utask)

    finally:
        heartbeat_stop.set()
        _release_task(taksid, hostname)
