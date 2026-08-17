#!/usr/bin/python
# -*- coding: utf-8 -*-

# hook_runner.py — Execute pre_connect / post_disconnect hooks defined in
# device_templates JSONB.  Hooks run before Netmiko connects (pre) and after
# Netmiko disconnects (post).  Per-hook failures are logged and skipped; they
# never abort the execution run.
#
# hook_runner.py MUST NOT import libs.util (import cycle).  RouterOS API
# credentials are injected by the caller via context['api_options'] built
# by util.build_api_options() in config_runner.

import logging
import importlib
import re

import requests

from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.check_routeros.routeros_check.helper import RouterOSVersion

log = logging.getLogger("hook_runner")


# ---------------------------------------------------------------------------
# Public entrypoint


def run_hooks(hooks, hook_type, device, template, context=None):
    """Execute a list of hook dicts and return accumulated context.

    :param hooks:   list of dicts from template.pre_connect or .post_disconnect
    :param hook_type: 'pre_connect' or 'post_disconnect'
    :param device:  Devices model instance
    :param template: dict (model_to_dict of DeviceTemplates row)
    :param context: mutable dict shared across hooks (None starts empty)
    :returns:       context dict
    """
    if not hooks:
        return context or {}
    if context is None:
        context = {}

    for idx, hook in enumerate(hooks):
        hook_type_name = hook.get("type", "unknown")
        try:
            if hook_type_name == "routeros_api":
                result = _execute_routeros_api_hook(hook, device, hook_type, context)
            elif hook_type_name == "http_request":
                result = _execute_http_hook(hook, device, hook_type, context)
            elif hook_type_name == "script":
                result = _execute_script_hook(hook, device, template, hook_type, context)
            else:
                log.warning("hook_runner: unknown hook type '%s' at index %d", hook_type_name, idx)
                result = {}
            if result:
                context.update(result)
        except Exception as e:
            log.error("hook_runner: hook %s[%d] (%s) failed: %s", hook_type, idx, hook_type_name, e)

    return context


# ---------------------------------------------------------------------------
# routeros_api hook


def _execute_routeros_api_hook(hook, device, hook_type, context):
    out = {}

    # 1. Resolve export_flags from DB current_firmware (cached by datagrabber / util.py)
    if hook.get("capture_export_flags"):
        version_str = getattr(device, "current_firmware", None)
        if version_str:
            try:
                clean_ver = str(version_str).partition(" ")[0].strip()
                m = re.match(r"^(\d+)", clean_ver)
                if m:
                    major = int(m.group(1))
                    out["export_flags"] = " show-sensitive" if major >= 7 else ""
                    log.info("hook_runner: RouterOS version from DB %s (device %s) => export_flags=%r", version_str, getattr(device, "ip", "?"), out["export_flags"])
            except Exception as e:
                log.warning("hook_runner: version parsing failed for %s: %s", version_str, e)

    api_options = context.get("api_options")
    if not api_options:
        if not out:
            log.warning("hook_runner: routeros_api hook missing context[api_options] - skipped")
        return out

    try:
        resource = RouterOSCheckResource(api_options)
        api = resource.api
    except Exception as e:
        log.warning("hook_runner: routeros_api connection to %s failed: %s", getattr(device, "ip", "?"), e)
        return out

    path = hook.get("path", "/ip/service")
    path_parts = path.strip("/").split("/")
    call = api.path(*path_parts)

    filter_criteria = hook.get("filter", {})
    results = tuple(call)
    target = None
    for row in results:
        match = True
        for key, val in filter_criteria.items():
            if str(row.get(key, "")) != str(val):
                match = False
                break
        if match:
            target = dict(row)
            break

    if not target:
        log.warning("hook_runner: routeros_api no match for filter %s at %s", filter_criteria, path)
        return out

    if hook_type == "pre_connect":
        action = hook.get("action", "enable")
        capture_field = hook.get("capture_field")
        save_key = hook.get("save_state_key")

        if capture_field and capture_field in target:
            try:
                val = target[capture_field]
                out["ssh_port"] = int(val) if str(val).isdigit() else val
            except (ValueError, TypeError):
                out["ssh_port"] = target[capture_field]

        if action == "enable":
            is_disabled = str(target.get("disabled", "")).lower() in ("true", "yes", "1")
            if is_disabled:
                api_id = target.get(".id")
                if api_id:
                    call.update(**{".id": api_id, "disabled": False})
                    log.info("hook_runner: enabled SSH on %s (was disabled)", device.ip)
            if save_key:
                out[save_key] = is_disabled

        if hook.get("capture_export_flags") and "export_flags" not in out:
            version_str = None
            if api:
                try:
                    ver_call = api.path("/system", "resource")
                    ver_results = tuple(ver_call)
                    if ver_results:
                        version_str = dict(ver_results[0]).get("version")
                except Exception as e:
                    log.warning("hook_runner: version detection via API failed: %s", e)

            if version_str:
                try:
                    clean_ver = str(version_str).partition(" ")[0].strip()
                    m = re.match(r"^(\d+)", clean_ver)
                    if m:
                        major = int(m.group(1))
                        out["export_flags"] = " show-sensitive" if major >= 7 else ""
                        log.info("hook_runner: RouterOS version via API %s (device %s) => export_flags='%s'",
                                 version_str, getattr(device, "ip", "?"), out["export_flags"])
                except Exception as e:
                    log.warning("hook_runner: version parsing failed for %s: %s", version_str, e)

    elif hook_type == "post_disconnect":
        action = hook.get("action", "restore")
        state_key = hook.get("state_key")
        if action == "restore" and state_key and context.get(state_key):
            api_id = target.get(".id")
            if api_id:
                call.update(**{".id": api_id, "disabled": True})
                log.info("hook_runner: disabled SSH on %s (restored original state)", device.ip)

    return out


# ---------------------------------------------------------------------------
# http_request hook


def _execute_http_hook(hook, device, hook_type, context):
    url = hook.get("url", "")
    method = hook.get("method", "GET").upper()
    headers = hook.get("headers") or {}
    body_template = hook.get("body")

    if not url:
        log.warning("hook_runner: http_request hook missing 'url'")
        return {}

    ip = device.ip
    url = url.replace("{ip}", ip).replace("{device_id}", str(device.id))

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            resp = requests.post(url, json=body_template, headers=headers, timeout=10)
        elif method == "PUT":
            resp = requests.put(url, json=body_template, headers=headers, timeout=10)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=10)
        else:
            return {}
        resp.raise_for_status()
        return resp.json() if resp.content else {}
    except requests.RequestException as e:
        log.error("hook_runner: http_request hook failed %s: %s", url, e)
        return {}


# ---------------------------------------------------------------------------
# script hook


def _execute_script_hook(hook, device, template, hook_type, context):
    module_path = hook.get("module", "")
    function_name = hook.get("function", "")
    if not module_path or not function_name:
        log.warning("hook_runner: script hook missing 'module' or 'function'")
        return {}

    try:
        mod = importlib.import_module(module_path)
        func = getattr(mod, function_name)
        return func(device=device, template=template, hook_type=hook_type, context=context)
    except (ImportError, AttributeError) as e:
        log.error("hook_runner: script hook %s.%s failed: %s", module_path, function_name, e)
        return {}
