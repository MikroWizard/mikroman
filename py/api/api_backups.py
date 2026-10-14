#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_backups.py: API for managing backups
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request, jsonify, session
from libs.db import db_tasks, db_backups, db_device, db_syslog, db_user_group_perm
from libs.db.db_user_tasks import UserTasks, Snippets
from libs import util
from libs import job_control
from libs.webutil import app, login_required, buildResponse, get_myself, get_ip, get_agent
import bgtasks
import logging
import json
import datetime
from functools import reduce
import operator

try:
    from libs.db.db_config_versions import CommandExecutionLog
except ImportError:
    CommandExecutionLog = None

try:
    from libs.db.db_snippet_pro import SnippetSequencesPro
except ImportError:
    SnippetSequencesPro = None

try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False
    pass

log = logging.getLogger("api.firmware")


@app.route('/api/backup/make', methods=['POST'])
@login_required(role='admin', perm={'backup': 'write'})
def backup_create():
    """Start a backup of the user's devices ("0" = all of them). The background job gets
    device ids only (permission filtered here). When a backup is already running the
    request is queued and runs after it; 'status' tells the UI that one was running."""
    input = request.json or {}
    devids = input.get('devids', False)
    if not devids:
        return buildResponse({'status': 'failed'}, 200, error="No devices selected")
    uid = session.get("userid") or False
    running = job_control.job_running(120)
    if devids == "0":
        devices = db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid)
    else:
        if not isinstance(devids, (list, tuple)):
            devids = [devids]
        devices = db_user_group_perm.DevUserGroupPermRel.get_user_devices_by_ids(uid, devids)
    device_ids = sorted({d.id for d in devices})
    if not device_ids:
        return buildResponse({'status': 'failed'}, 200, error="No permitted devices selected")
    try:
        job_control.check_spool_size({"device_ids": device_ids, "uid": uid})
    except ValueError as e:
        return buildResponse({'status': 'failed'}, 200, error="Too many devices for one backup request: {}".format(e))
    db_syslog.add_syslog_event(get_myself(), "Backup Managment", "Create", get_ip(), get_agent(), json.dumps(input))
    bgtasks.backup_devices(device_ids=device_ids, uid=uid)
    return buildResponse([{'status': running, 'queued': running, 'device_count': len(device_ids)}], 200)


@app.route('/api/backup/list', methods=['POST'])
@login_required(role='admin', perm={'backup': 'read'})
def backup_list():
    input = request.json or {}
    event_start_time = input.get('start_time', False)
    event_end_time = input.get('end_time', False)
    devid = input.get('devid', False)
    search = input.get('search')
    source_filter = input.get('source', 'backup')
    uid = session.get("userid") or False
    if not devid:
        devs = list(db_user_group_perm.DevUserGroupPermRel.get_user_devices(uid))
        dev_ids = [dev.id for dev in devs]
    else:
        dev = db_device.get_device(devid)
        if not dev:
            return buildResponse({'status': 'failed'}, 200, error="Wrong Data")
        dev_ids = [devid]
    backups = db_backups.Backups
    clauses = []
    clauses.append(backups.devid << dev_ids)
    if event_start_time:
        event_start_time = event_start_time.split(".000Z")[0]
        event_start_time = datetime.datetime.strptime(event_start_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(backups.created >= event_start_time)
    else:
        clauses.append(backups.created >= datetime.datetime.now() - datetime.timedelta(days=1))
    if event_end_time:
        event_end_time = event_end_time.split(".000Z")[0]
        event_end_time = datetime.datetime.strptime(event_end_time, "%Y-%m-%dT%H:%M:%S")
        clauses.append(backups.created <= event_end_time)
    else:
        clauses.append(backups.created <= datetime.datetime.now())

    try:
        if len(clauses):
            expr = reduce(operator.and_, clauses)
            query = backups.select().where(expr)
        else:
            query = backups.select()
        query = query.order_by(backups.id.desc())
        backups = list(query)
    except Exception as e:
        log.error(e)
        return buildResponse({"status": "failed", "err": str(e)}, 200)

    if search and ISPRO:
        backups = utilpro.search_in_backups(search, backups)

    # Correlate metadata with CommandExecutionLog & UserTasks (v2.0.0 multi-brand support + v1.3.1 backward compatibility)
    # Each backup row is matched with the run of the same device that stored its raw file,
    # nearest in time: unchanged configurations share one raw file (raw dedup), so the newest
    # run with that file is not necessarily the one that wrote this row.
    log_for_backup = {}
    if CommandExecutionLog and len(backups):
        try:
            ids = [b.id for b in backups if b.devid_id and b.dir and "raw/" in b.dir]
            pairs = db_backups.runs_of_backups(ids)
            log_ids = sorted({lid for lid in pairs.values() if lid})
            logs = {}
            for i in range(0, len(log_ids), 1000):
                for l in CommandExecutionLog.select().where(CommandExecutionLog.id << log_ids[i:i + 1000]):
                    logs[l.id] = l
            log_for_backup = {bid: logs[lid] for bid, lid in pairs.items() if lid in logs}
        except Exception as ex:
            log.warning("api_backups: CommandExecutionLog lookup failed: %s", ex)

    reply = []
    for back in backups:
        data = {}
        back_dev_id = None
        filesize = getattr(back, "filesize", None) or getattr(back, "size", 0)
        created = getattr(back, "created", None) or getattr(back, "date", "")
        if back.devid:
            dev = back.devid
            back_dev_id = dev.id if hasattr(dev, "id") else dev
            data['id'] = back.id
            data['filesize'] = util.sizeof_fmt(filesize)
            data['created'] = created
            data['devname'] = dev.name if hasattr(dev, "name") else str(back_dev_id)
            data['devip'] = dev.ip if hasattr(dev, "ip") else ""
            data['devmac'] = dev.mac if hasattr(dev, "mac") else ""
        else:
            data['id'] = back.id
            data['filesize'] = util.sizeof_fmt(filesize)
            data['created'] = created
            data['devname'] = 'Deleted  Device'
            data['devip'] = ''
            data['devmac'] = ''

        # Determine source metadata
        source = "backup"
        source_name = "Config Backup"
        command = "export"
        source_id = None

        exec_log = log_for_backup.get(back.id)

        if exec_log:
            cmd_key = exec_log.command_key
            cmd_str = exec_log.command_string or ""
            utask = exec_log.user_task_id

            ttype = getattr(utask, 'task_type', None) if utask else None
            snip = getattr(utask, 'snippetid', None) if utask else None
            snip_name = getattr(snip, 'name', None) if snip else None
            snip_id = getattr(snip, 'id', None) if snip else None
            if not snip_name and utask and getattr(utask, 'data', None):
                try:
                    udata = json.loads(utask.data)
                    snip_name = udata.get('snippet', {}).get('name')
                    snip_id = udata.get('snippet', {}).get('id')
                except Exception:
                    pass

            if ttype in ("snippet", "snipet_exec"):
                source = "snippet"
                source_name = snip_name or getattr(utask, 'name', 'Snippet')
                source_id = snip_id or getattr(utask, 'id', None)
                command = cmd_str or "Snippet Execution"
            elif ttype in ("sequence", "sequence_exec"):
                source = "sequence"
                seq_name = getattr(utask, 'name', 'Sequence')
                if seq_name and seq_name.startswith("Manual Run:"):
                    seq_name = "Sequence Execution"
                source_name = seq_name
                source_id = getattr(utask, 'id', None)
                command = cmd_str or "Sequence Execution"
            elif cmd_key == "show_config" or (not cmd_key and ("/export" in cmd_str or "export" in cmd_str)):
                source = "backup"
                source_name = getattr(utask, 'name', 'Config Backup') if utask else "Config Backup"
                command = cmd_str or "show_config"
            elif cmd_key and cmd_key.startswith("show_"):
                source = "command"
                source_name = f"Show Run ({cmd_key})"
                command = cmd_str or cmd_key
            elif cmd_str and not cmd_key:
                source = "snippet"
                source_name = getattr(utask, 'name', 'Snippet') if utask else "Command / Snippet"
                source_id = getattr(utask, 'id', None) if utask else None
                command = cmd_str
            else:
                source = "backup"
                source_name = getattr(utask, 'name', 'System Backup') if utask else "System Backup"
                command = cmd_str or "export"
        else:
            # Legacy v1.3.1 path / direct store_config()
            source = "backup"
            source_name = "System Backup"
            command = "export"

        data['source'] = source
        data['source_name'] = source_name
        data['command'] = command
        data['source_id'] = source_id

        # Filter based on requested source
        if source_filter == "backup" and source != "backup":
            continue
        elif source_filter in ("snippet", "sequence", "command", "manual") and source != source_filter:
            continue

        reply.append(data)

    return buildResponse(reply, 200)


@app.route('/api/backup/get', methods=['POST'])
@login_required(role='admin', perm={'backup': 'read'})
def backup_get():
    input = request.json or {}
    id = input.get('id')
    try:
        back = db_backups.get_backup(id)
        path = back.dir
        with open(path, 'r') as file:
            file_content = file.read()
    except Exception as e:
        log.error(e)
        return buildResponse({"status": "failed"}, 200)
    return buildResponse({"content": file_content}, 200)


@app.route('/api/backup/status', methods=['POST'])
@login_required(role='admin', perm={'backup': 'read'})
def backup_status():
    status = db_tasks.update_check_status().status
    return jsonify({'status': status})
