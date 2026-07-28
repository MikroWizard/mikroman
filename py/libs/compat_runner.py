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


def run_snippet(dev, snippet, template_key=None):
    content = snippet.content if hasattr(snippet, "content") else str(snippet)
    result = run_device_job({
        "device_id": dev.id,
        "snippet_content": content,
        "command_key": template_key,
        "capture_output": True,
        "skip_versioning": True,
    })
    if result["status"] == "ok":
        return result.get("output_raw") or result.get("output_normalized") or "executed successfully"
    return False


def run_snippets(dev, snippet, q, template_key=None):
    result = run_snippet(dev, snippet, template_key=template_key)
    q.put({
        "devid": dev.id, "devip": dev.ip, "devname": dev.name,
        "status": True if result else False,
        "result": result if result else "Exec Failed",
    })
    return result
