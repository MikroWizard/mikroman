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
from libs import util, firm_lib
from libs import job_control
from libs.db import db_user_tasks, db_tasks
from libs.db.db_device import Devices
from libs.db.db import database, tune_process_db_pool
from libs.webutil import app, login_required, get_myself, buildResponse
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

from libs import config_runner as cfg_runner

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
    tune_process_db_pool(role="cli", num_devices=len(devices))

    def worker(dev_id):
        res = cfg_runner.run_device_job({"device_id": dev_id, "command_key": "show_config"})
        ok = res.get("status") == "ok"
        return {"id": dev_id, "devid": dev_id, "devip": res.get("device_ip", ""),
                "devname": res.get("device_name", ""), "status": ok, "state": ok,
                "reason": None if ok else (res.get("error") or "Backup failed")[:500]}

    def skipped(dev_id, reason, message):
        return {"id": dev_id, "devid": dev_id, "status": False, "state": False, "reason": message,
                "skipped": reason if reason != "error" else None}

    res = job_control.run_devices([d.id for d in devices], worker, skipped=skipped)
    with database.connection_context():
        for qres in res:
            if not qres.get("state", True) and not qres.get("skipped"):
                util.log_alert("backup", qres.get("id", 0), "Backup failed")
    return res


def run_snippets(devices, snippet, template_key=None, user_task_id=None, snippet_id=None, store_in_backup=False):
    tune_process_db_pool(role="cli", num_devices=len(devices))

    def worker(dev_id):
        with database.connection_context():
            dev = Devices.get_by_id(dev_id)
            devip, devname = dev.ip, getattr(dev, "name", "")
        r = cfg_runner.run_device_job({
            "device_id": dev_id, "snippet_content": snippet, "snippet_id": snippet_id,
            "command_key": template_key, "user_task_id": user_task_id, "capture_output": True,
            "store_in_backup": store_in_backup, "skip_versioning": not store_in_backup,
        })
        ok = r.get("status") == "ok"
        result = (r.get("output_raw") or r.get("output_normalized") or "executed successfully") if ok else False
        return {"id": dev_id, "devid": dev_id, "devip": devip, "devname": devname, "status": ok, "state": ok,
                "result": result, "error": None if ok else r.get("error")}

    def skipped(dev_id, reason, message):
        return {"id": dev_id, "devid": dev_id, "status": False, "state": False, "result": False,
                "error": message, "skipped": reason if reason != "error" else None}

    res = job_control.run_devices([d.id for d in devices], worker, skipped=skipped)
    with database.connection_context():
        for qres in res:
            if "result" in qres and not qres["result"] and not qres.get("skipped"):
                util.log_alert("run_snippet", qres.get("id", 0), "Run Snippet failed")
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
                try:
                    with database.connection_context():
                        db_tasks.add_task_result("snippet", json.dumps(res), json.dumps({"task_id": utask.id}), utask.id)
                except Exception as e:
                    log.error("scheduled snippet results of task %s not saved: %s", utask.id, e)

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
            log.info("firmware update task")
            # Pro task runner with a valid license; otherwise the free one (no Latest Cloud,
            # no PtP ordering) so the scheduled update still runs
            if ISPRO and utilpro.check_license_dev_limit_exp():
                res = utilpro.run_firmware_task(utask)
            else:
                res = firm_lib.run_firmware_task(utask)

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
