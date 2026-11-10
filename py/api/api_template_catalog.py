#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_template_catalog.py: template catalog updates in the Template Manager (libs/template_catalog.py)
# MikroWizard.com , Mikrotik router management solution

import datetime
import json
import logging

from flask import request

from _version import __version__
from libs import template_catalog as tc
from libs import util
from libs.db import db_sysconfig, db_syslog
from libs.webutil import app, buildResponse, get_agent, get_ip, get_myself, login_required

try:
    from libs import utilpro  # noqa: F401
    ISPRO = True
except ImportError:
    ISPRO = False

log = logging.getLogger("api.template_catalog")


def _inactive():
    if tc.available():
        return None
    return buildResponse({"status": "failed", "available": False,
                          "err": "Template updates need migration 067 (run the database migration)"}, 200)


def _user():
    me = get_myself()
    return getattr(me, "username", None) or str(getattr(me, "id", "admin"))


def _audit(action, data):
    db_syslog.add_syslog_event(get_myself(), "Template Catalog", action, get_ip(), get_agent(), json.dumps(data))


def update_check_params():
    """The same identification the update checker sends to mikrowizard.com."""
    hwid = util.generate_serial_number(util.get_ethernet_wifi_interfaces())
    install_date = db_sysconfig.get_sysconfig("install_date")
    serial = hwid
    if install_date:
        serial = hwid + "-" + datetime.datetime.strptime(install_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
    return {"serial_number": serial, "username": (db_sysconfig.get_sysconfig("username") or "").strip(),
            "version": __version__, "ISPRO": ISPRO}


@app.route("/api/pam/templates/catalog/status", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def template_catalog_status():
    blocked = _inactive()
    if blocked:
        return blocked
    return buildResponse(dict(tc.status(), status="success"), 200)


@app.route("/api/pam/templates/catalog/updates", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def template_catalog_updates():
    blocked = _inactive()
    if blocked:
        return blocked
    return buildResponse({"status": "success", "updates": [p for p in tc.plan() if p["kind"] != "adopt"]}, 200)


@app.route("/api/pam/templates/catalog/apply", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_apply():
    blocked = _inactive()
    if blocked:
        return blocked
    data = request.json or {}
    try:
        if data.get("all_safe"):
            done = tc.apply_safe(user=_user())
            _audit("Apply", {"all_safe": True, "templates": done})
            return buildResponse({"status": "success", "results": done}, 200)
        key = data.get("key")
        choices = {k: v for k, v in (data.get("choices") or {}).items() if v in ("mine", "new")}
        result = tc.apply(key, choices=choices, user=_user())
        _audit("Apply", {"key": key, "choices": choices, "result": result})
        return buildResponse({"status": "success", "result": result}, 200)
    except tc.CatalogError as e:
        return buildResponse({"status": "failed", "err": str(e)}, 200)


@app.route("/api/pam/templates/catalog/skip", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_skip():
    blocked = _inactive()
    if blocked:
        return blocked
    key = (request.json or {}).get("key")
    try:
        tc.skip(key, user=_user())
    except tc.CatalogError as e:
        return buildResponse({"status": "failed", "err": str(e)}, 200)
    _audit("Skip", {"key": key})
    return buildResponse({"status": "success"}, 200)


@app.route("/api/pam/templates/catalog/history", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def template_catalog_history():
    blocked = _inactive()
    if blocked:
        return blocked
    tid = int((request.json or {}).get("template_id") or 0)
    return buildResponse({"status": "success", "history": tc.history(tid)}, 200)


@app.route("/api/pam/templates/catalog/revert", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_revert():
    blocked = _inactive()
    if blocked:
        return blocked
    hid = int((request.json or {}).get("history_id") or 0)
    try:
        result = tc.revert(hid, user=_user())
    except Exception as e:
        return buildResponse({"status": "failed", "err": str(e)}, 200)
    _audit("Revert", {"history_id": hid})
    return buildResponse({"status": "success", "result": result}, 200)


@app.route("/api/pam/templates/catalog/check_now", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_check_now():
    blocked = _inactive()
    if blocked:
        return blocked
    result = tc.periodic(update_check_params(), force=True)
    return buildResponse(dict(tc.status(), status="success", result=result), 200)


@app.route("/api/pam/templates/catalog/import", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_import():
    """Signed catalog file for installs without internet access."""
    blocked = _inactive()
    if blocked:
        return blocked
    data = request.json or {}
    try:
        stored, version = tc.store((data.get("catalog") or "").encode("utf-8"), data.get("signature") or "", "file")
    except tc.CatalogError as e:
        return buildResponse({"status": "failed", "err": str(e)}, 200)
    _audit("Import", {"catalog_version": version, "stored": stored})
    return buildResponse({"status": "success", "stored": stored, "catalog_version": version}, 200)


@app.route("/api/pam/templates/catalog/settings", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def template_catalog_settings():
    data = request.json or {}
    mode = data.get("mode")
    channel = data.get("channel")
    if mode not in ("notify", "auto", "off") or channel not in ("stable", "beta"):
        return buildResponse({"status": "failed", "err": "mode: notify/auto/off, channel: stable/beta"}, 200)
    db_sysconfig.set_sysconfig("template_update_mode", mode)
    db_sysconfig.set_sysconfig("template_channel", channel)
    _audit("Settings", {"mode": mode, "channel": channel})
    return buildResponse({"status": "success"}, 200)
