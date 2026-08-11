#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import logging
import secrets
import requests
from flask import request
from libs.webutil import app, login_required, buildResponse

log = logging.getLogger("api.ssl")

SSL_AGENT_URL = "http://host.docker.internal/ssl-internal"
TOKEN_FILE = "/conf/ssl-agent-token"
TOKEN_FILE_HOST = "/opt/mikrowizard/ssl-agent-token"
TOKEN_FILE_FALLBACK = "/tmp/mw-ssl-agent-token"


def _get_token():
    for path in [TOKEN_FILE, TOKEN_FILE_HOST, TOKEN_FILE_FALLBACK]:
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    token = f.read().strip()
                    if token:
                        return token
        except Exception:
            pass

    import secrets as _secrets
    token = _secrets.token_hex(32)
    for path in [TOKEN_FILE_HOST, TOKEN_FILE_FALLBACK, TOKEN_FILE]:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(token)
            os.chmod(path, 0o644)
            log.info("Generated new SSL agent token at %s", path)
            return token
        except Exception as e:
            log.warning("Could not write token to %s: %s", path, e)
    return token


def _proxy_request(endpoint, body=None, method="POST"):
    token = _get_token()
    headers = {"X-SSL-Agent-Token": token, "Content-Type": "application/json"}
    timeout = 360

    urls = [
        ("http://127.0.0.1:8199/%s" % endpoint.lstrip("/"), 3),
        ("%s/%s" % (SSL_AGENT_URL, endpoint.lstrip("/")), 5),
    ]

    for url, connect_timeout in urls:
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=connect_timeout)
            else:
                resp = requests.post(url, json=body or {}, headers=headers, timeout=connect_timeout)

            if resp.status_code == 401:
                continue

            return resp.json(), resp.status_code
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    return {"error": "ssl_agent_unreachable", "detail": "SSL agent is not running. Start ssl-agent first."}, 503


@app.route('/api/ssl/status', methods=['POST'])
@login_required(role='admin', perm={'settings': 'read'})
def ssl_status():
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
    data, code = _proxy_request("letsencrypt/request", request.get_json() or {})
    return buildResponse(data, code)


@app.route('/api/ssl/letsencrypt/renew', methods=['POST'])
@login_required(role='admin', perm={'settings': 'write'})
def ssl_letsencrypt_renew():
    data, code = _proxy_request("letsencrypt/renew", request.get_json() or {})
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
    content = ""
    script_path = "/conf/recreate-ssl.sh"
    if os.path.exists(script_path):
        with open(script_path, "r") as f:
            content = f.read()
    return buildResponse({"script": content})
