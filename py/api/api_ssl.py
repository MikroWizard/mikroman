#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import logging
import time
import secrets as _secrets
import requests
from flask import request
from libs.webutil import app, login_required, buildResponse
import config
from libs.db.db_sysconfig import get_sysconfig

log = logging.getLogger("api.ssl")

SSL_AGENT_URL = "http://host.docker.internal/ssl-internal"
TOKEN_KEY = "ssl_agent_token"


def _get_token(reload_disk=False):
    if not reload_disk:
        token = config.srvconf.get(TOKEN_KEY)
        if token:
            return token

    # Check disk first
    conf_path = os.environ.get("PYSRV_CONFIG_PATH", "/conf/server-conf.json")
    try:
        if os.path.exists(conf_path):
            with open(conf_path, "r") as f:
                disk_conf = json.load(f)
            token = disk_conf.get(TOKEN_KEY)
            if token:
                config.srvconf[TOKEN_KEY] = token
                log.info("Loaded ssl_agent_token from %s", conf_path)
                return token
    except Exception as e:
        log.warning("Could not read %s for token: %s", conf_path, e)

    # Generate and persist only if missing everywhere
    token = _secrets.token_hex(32)
    config.srvconf[TOKEN_KEY] = token
    try:
        disk_conf = {}
        if os.path.exists(conf_path):
            with open(conf_path, "r") as f:
                disk_conf = json.load(f)
        disk_conf[TOKEN_KEY] = token
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, "w") as f:
            json.dump(disk_conf, f, indent=2)
        log.info("Persisted ssl_agent_token to %s", conf_path)
    except Exception as e:
        log.warning("Could not persist token: %s", e)
    return token


def _proxy_request(endpoint, body=None, method="POST", timeout=5):
    token = _get_token()
    headers = {"X-SSL-Agent-Token": token, "Content-Type": "application/json"}

    urls = [
        ("http://127.0.0.1:8199/%s" % endpoint.lstrip("/"), min(3, timeout)),
        ("http://127.0.0.1/ssl-internal/%s" % endpoint.lstrip("/"), timeout),
        ("http://localhost/ssl-internal/%s" % endpoint.lstrip("/"), timeout),
        ("%s/%s" % (SSL_AGENT_URL, endpoint.lstrip("/")), timeout),
    ]

    for attempt in range(3):
        for url, connect_timeout in urls:
            try:
                if method == "GET":
                    resp = requests.get(url, headers=headers, timeout=connect_timeout)
                else:
                    resp = requests.post(url, json=body or {}, headers=headers, timeout=connect_timeout)

                if resp.status_code == 401:
                    log.warning("ssl-agent returned 401 on %s, reloading token from disk...", url)
                    token = _get_token(reload_disk=True)
                    headers["X-SSL-Agent-Token"] = token
                    continue

                try:
                    return resp.json(), resp.status_code
                except Exception:
                    log.warning("ssl-agent response from %s was not valid JSON (status %s): %s",
                                url, resp.status_code, resp.text[:200])
                    continue

            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                log.warning("ssl-agent proxy request to %s error: %s", url, e)
                continue
        time.sleep(1)

    return {"error": "ssl_agent_unreachable", "detail": "SSL agent is not running. Start ssl-agent first."}, 503


@app.route('/api/ssl/status', methods=['POST'])
@login_required(role='admin', perm={'settings': 'read'})
def ssl_status():
    log.info("Requesting SSL status from agent")
    data, code = _proxy_request("status")
    return buildResponse(data, code)


@app.route('/api/ssl/generate-csr', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_generate_csr():
    data, code = _proxy_request("generate-csr", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/install-cert', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_install_cert():
    data, code = _proxy_request("install-cert", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/request', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_letsencrypt_request():
    data, code = _proxy_request("letsencrypt/request", request.get_json() or {}, timeout=120)
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/renew', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_letsencrypt_renew():
    data, code = _proxy_request("letsencrypt/renew", request.get_json() or {}, timeout=120)
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/revoke', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_letsencrypt_revoke():
    data, code = _proxy_request("letsencrypt/revoke", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/delete', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_letsencrypt_delete():
    data, code = _proxy_request("letsencrypt/delete", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/force-ssl', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_force_ssl():
    data, code = _proxy_request("force-ssl", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/disable', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_disable():
    data, code = _proxy_request("disable", {})
    return buildResponse(data, code)


@app.route('/api/ssl/nginx/test', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_nginx_test():
    data, code = _proxy_request("nginx/test")
    return buildResponse(data, code)


@app.route('/api/ssl/nginx/reload', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_nginx_reload():
    data, code = _proxy_request("nginx/reload")
    return buildResponse(data, code)


@app.route('/api/ssl/nginx/config', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_nginx_config():
    data, code = _proxy_request("nginx/config", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/migration-script', methods=['POST'])
@login_required(role='admin', perm={'settings': 'read'})
def ssl_migration_script():
    data, code = _proxy_request("migration-script/generate", {})
    return buildResponse(data, code)


@app.route('/api/ssl/install-certbot', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_install_certbot():
    data, code = _proxy_request("install-certbot", {})
    return buildResponse(data, code)


@app.route('/api/ssl/install-certbot/status', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_install_certbot_status():
    data, code = _proxy_request("install-certbot/status", {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/dns-manual/start', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_dns_manual_start():
    data, code = _proxy_request("letsencrypt/dns-manual/start", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/dns-manual/status', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_dns_manual_status():
    data, code = _proxy_request("letsencrypt/dns-manual/status", {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/dns-manual/continue', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_dns_manual_continue():
    data, code = _proxy_request("letsencrypt/dns-manual/continue", {})
    return buildResponse(data, code)
