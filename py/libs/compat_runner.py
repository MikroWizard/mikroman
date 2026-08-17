#!/usr/bin/python
# -*- coding: utf-8 -*-

# compat_runner.py — Legacy entry-point shims routing through config_runner.
# Separated from util.py to prevent import cycles.

from libs.config_runner import run_device_job


def backup_router(dev):
    result = run_device_job({
        "device_id": dev.id, "command_key": "show_config",
    })
    return result.get("status") == "ok"


def backup_routers(dev, q):
    status = backup_router(dev)
    q.put({"id": dev.id, "devip": dev.ip, "state": status})


def run_snippet(dev, snippet, template_key=None, user_task_id=None, snippet_id=None, store_in_backup=False):
    content = snippet.content if hasattr(snippet, "content") else str(snippet)
    snip_id = snippet_id or (snippet.id if hasattr(snippet, "id") else None)
    result = run_device_job({
        "device_id": dev.id,
        "snippet_content": content,
        "snippet_id": snip_id,
        "command_key": template_key,
        "user_task_id": user_task_id,
        "capture_output": True,
        "store_in_backup": store_in_backup,
        "skip_versioning": not store_in_backup,
    })
    if result["status"] == "ok":
        return result.get("output_raw") or result.get("output_normalized") or "executed successfully"
    return False


def run_snippets(dev, snippet, q, template_key=None, user_task_id=None, snippet_id=None, store_in_backup=False):
    result = run_snippet(dev, snippet, template_key=template_key, user_task_id=user_task_id, snippet_id=snippet_id, store_in_backup=store_in_backup)
    q.put({
        "devid": dev.id, "devip": dev.ip, "devname": dev.name,
        "status": True if result else False,
        "result": result if result else "Exec Failed",
    })
    return result
