#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_executions.py: FREE API for execution triggering, status, history, and CSV export.
# MikroWizard.com , Mikrotik router management solution

import json
import csv
import io
import logging
import uuid

from flask import request, Response, session

from libs.db import db_user_tasks, db_syslog, db_tasks, db_user_group_perm
from libs.db.db_config_versions import list_executions
from libs.webutil import app, login_required, buildResponse, get_myself, get_ip, get_agent
import bgtasks

log = logging.getLogger("api.executions")


@app.route("/api/executions/list", methods=["POST"])
@login_required(role="admin", perm={"task": "read"})
def executions_list():
    input_data = request.json or {}
    device_id = input_data.get("device_id")
    execution_run_id = input_data.get("execution_run_id")
    user_task_id = input_data.get("user_task_id")
    page = int(input_data.get("page", 1) or 1)
    per_page = int(input_data.get("per_page", 50) or 50)

    executions, total = list_executions(
        device_id=int(device_id) if device_id else None,
        execution_run_id=execution_run_id,
        user_task_id=int(user_task_id) if user_task_id else None,
        page=page, per_page=per_page,
    )
    data = []
    for e in executions:
        did = e.device_id
        did = did.id if hasattr(did, 'id') else int(did) if did else 0
        data.append({
            "id": e.id, "execution_run_id": str(e.execution_run_id),
            "device_id": did, "command_key": e.command_key,
            "command_string": e.command_string,
            "status": e.status, "error_message": e.error_message,
            "duration_ms": e.duration_ms, "is_versioned": e.is_versioned,
            "version_id": e.version_id,
            "raw_size_bytes": e.raw_size_bytes or 0,
            "executed_at": e.executed_at.isoformat() if e.executed_at else None,
        })
    return buildResponse({"status": "success", "data": data, "total": total, "page": page, "per_page": per_page}, 200)


@app.route("/api/executions/run", methods=["POST"])
@login_required(role="admin", perm={"task": "write"})
def executions_run():
    user = get_myself()
    input_data = request.json or {}
    device_ids = input_data.get("device_ids", [])
    if not device_ids:
        return buildResponse({"status": "failed", "error": "device_ids required"}, 400)

    # Resolve device list with permission scoping
    allowed = db_user_group_perm.DevUserGroupPermRel.get_user_devices(user.id)
    allowed_ids = {d.id for d in allowed}
    # Coerce device_ids to integers (in case frontend sends objects)
    coerced = [int(d) if not isinstance(d, int) else d for d in device_ids]
    selected = [did for did in coerced if did in allowed_ids]
    if not selected:
        return buildResponse({"status": "failed", "error": "No permitted devices selected"}, 400)

    # Validate: at least one of command_key, custom_command, snippet_id
    if not input_data.get("command_key") and not input_data.get("custom_command") and not input_data.get("snippet_id"):
        return buildResponse({"status": "failed", "error": "No command specified (command_key/custom_command/snippet_id)"}, 400)

    run_id = str(uuid.uuid4())

    # Create signal task for cancel tracking
    try:
        db_tasks.create_exec_multi_brand_task(task_id=run_id)
    except Exception:
        pass

    db_syslog.add_syslog_event(user, "Execution", "Run", get_ip(), get_agent(), json.dumps(input_data))

    bgtasks.exec_multi_brand(
        device_ids=selected,
        command_key=input_data.get("command_key"),
        custom_command=input_data.get("custom_command"),
        snippet_id=input_data.get("snippet_id"),
        snippet_content=input_data.get("snippet_content"),
        is_config_mode=input_data.get("is_config_mode", False),
        user_task_id=input_data.get("user_task_id"),
        run_id=run_id,
    )

    return buildResponse({"status": "success", "execution_run_id": run_id, "device_count": len(selected)}, 200)


@app.route("/api/executions/status", methods=["POST"])
@login_required(role="admin", perm={"task": "read"})
def executions_status():
    input_data = request.json or {}
    execution_run_id = input_data.get("execution_run_id")
    if not execution_run_id:
        return buildResponse({"status": "failed", "error": "execution_run_id required"}, 400)

    status_info = {"finished": False, "device_count": 0, "ok_count": 0, "error_count": 0, "version_count": 0}
    try:
        from libs.db.db_config_versions import CommandExecutionLog
        from playhouse.shortcuts import fn
        logs = list(CommandExecutionLog.select().where(
            CommandExecutionLog.execution_run_id == execution_run_id
        ))
        status_info["device_count"] = len(logs)
        status_info["ok_count"] = sum(1 for l in logs if l.status == "ok")
        status_info["error_count"] = sum(1 for l in logs if l.status in ("error", "timeout", "auth_error"))
        status_info["version_count"] = sum(1 for l in logs if l.is_versioned)
    except Exception:
        pass

    try:
        sig = db_tasks.get_task_by_signal(185)
        status_info["finished"] = not bool(sig.status)
    except Exception:
        pass

    return buildResponse({"status": "success", "data": status_info}, 200)


@app.route("/api/executions/export", methods=["POST"])
@login_required(role="admin", perm={"task": "read"})
def executions_export():
    input_data = request.json or {}
    execution_run_id = input_data.get("execution_run_id")
    if not execution_run_id:
        return buildResponse({"status": "failed", "error": "execution_run_id required"}, 400)

    from libs.db.db_config_versions import CommandExecutionLog
    from libs.db.db_device import Devices

    logs = list(CommandExecutionLog.select().where(
        CommandExecutionLog.execution_run_id == execution_run_id
    ).order_by(CommandExecutionLog.device_id))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["device_id", "device_name", "device_ip", "command_key", "status",
                       "is_changed", "version_num", "error_message", "duration_ms", "executed_at"])

    device_names = {}
    unique_dev_ids = set()
    for l in logs:
        did = l.device_id
        did = did.id if hasattr(did, 'id') else int(did) if did else 0
        unique_dev_ids.add(did)
    for did in unique_dev_ids:
        try:
            dev = Devices.get_by_id(did)
            device_names[did] = (dev.name, dev.ip)
        except Exception:
            device_names[did] = ("Unknown", "")

    for log_entry in logs:
        did = log_entry.device_id
        did = did.id if hasattr(did, 'id') else int(did) if did else 0
        dname, dip = device_names.get(did, ("Unknown", ""))
        version_num = ""
        if log_entry.version_id:
            try:
                from libs.db.db_config_versions import ConfigVersions
                ver = ConfigVersions.get_by_id(log_entry.version_id)
                version_num = str(ver.version_num)
            except Exception:
                pass
        writer.writerow([
            did, dname, dip,
            log_entry.command_key or "", log_entry.status,
            "true" if log_entry.is_versioned else "false",
            version_num,
            log_entry.error_message or "", log_entry.duration_ms or 0,
            log_entry.executed_at.isoformat() if log_entry.executed_at else "",
        ])

    csv_content = output.getvalue()
    return Response(csv_content, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=executions.csv"})
