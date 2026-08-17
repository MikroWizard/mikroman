#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import logging
from flask import request
from libs.webutil import app, buildResponse, login_required
from libs.db.db_pam import DeviceBrands, DeviceTemplates, Credentials, DeviceConnections
try:
    from libs.db.db_pam_pro import ConnectionSessions, create_session
    ISPRO = True
except ImportError:
    ISPRO = False
from libs.db.db_device import Devices
from libs.template_service import TemplateService
from libs.credential_service import CredentialService

log = logging.getLogger('api_pam')

try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False

def _license_blocked():
    """Return a blocking response when the license is invalid/over device limit, else None."""
    if ISPRO and not utilpro.check_license_dev_limit_exp():
        return buildResponse({'status': 'failed'}, 200, error="License Expired")
    return None

def _user_can_access_device(user, device_id):
    """Check System B: user must be admin/superuser OR belong to a device group containing device_id."""
    if user.role in ('admin', 'superuser'):
        return True
    from libs.db.db_user_group_perm import DevUserGroupPermRel
    user_devices = DevUserGroupPermRel.get_user_devices(user.id)
    return user_devices.where(Devices.id == device_id).exists()

# ==========================================
# Device Brands
# ==========================================
@app.route("/api/pam/brands/list", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def list_brands():
    blocked = _license_blocked()
    if blocked:
        return blocked
    brands = list(DeviceBrands.select().dicts())
    return buildResponse(brands, 200)

@app.route("/api/pam/brands/create", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def create_brand():
    data = request.json or {}
    slug = data.get('brand', '').strip().lower().replace(' ', '_')
    display_name = data.get('display_name', '').strip()
    if not slug or not display_name:
        return buildResponse({'status': 'failed', 'err': 'brand slug and display_name required'}, 200)
    if DeviceBrands.select().where(DeviceBrands.brand == slug).exists():
        return buildResponse({'status': 'failed', 'err': f"Brand '{slug}' already exists"}, 200)
    try:
        now = datetime.datetime.utcnow()
        DeviceBrands.create(brand=slug, display_name=display_name, is_active=True, is_system=False, created=now)
        return buildResponse({'status': 'success', 'brand': slug}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/brands/update", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def update_brand():
    data = request.json or {}
    brand = data.get('brand', '').strip()
    if not brand:
        return buildResponse({'status': 'failed', 'err': 'brand slug required'}, 200)
    try:
        b = DeviceBrands.get(DeviceBrands.brand == brand)
        if b.is_system:
            return buildResponse({'status': 'failed', 'err': 'System brands cannot be modified'}, 200)
        if 'display_name' in data and data['display_name']:
            b.display_name = data['display_name'].strip()
        if 'is_active' in data:
            b.is_active = bool(data['is_active'])
        b.save()
        return buildResponse({'status': 'success'}, 200)
    except DeviceBrands.DoesNotExist:
        return buildResponse({'status': 'failed', 'err': 'Brand not found'}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/brands/delete", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def delete_brand():
    brand = (request.json or {}).get('brand', '').strip()
    if not brand:
        return buildResponse({'status': 'failed', 'err': 'brand slug required'}, 200)
    try:
        b = DeviceBrands.get(DeviceBrands.brand == brand)
        if b.is_system:
            return buildResponse({'status': 'failed', 'err': 'System brands cannot be deleted'}, 200)
        # Check for dependent devices
        dev_count = Devices.select().where(Devices.device_type == brand).count()
        if dev_count > 0:
            return buildResponse({'status': 'failed', 'err': f'Cannot delete: {dev_count} device(s) use this brand'}, 200)
        # Check for dependent templates
        tmpl_count = DeviceTemplates.select().where(DeviceTemplates.brand == brand).count()
        if tmpl_count > 0:
            return buildResponse({'status': 'failed', 'err': f'Cannot delete: {tmpl_count} template(s) use this brand'}, 200)
        b.delete_instance()
        return buildResponse({'status': 'success'}, 200)
    except DeviceBrands.DoesNotExist:
        return buildResponse({'status': 'failed', 'err': 'Brand not found'}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

# ==========================================
# Device Templates
# ==========================================
@app.route("/api/pam/templates/list", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def list_templates():
    blocked = _license_blocked()
    if blocked:
        return blocked
    data = request.json or {}
    brand_id = data.get('brand_id')
    return buildResponse(TemplateService.list_templates(brand=brand_id), 200)

@app.route("/api/pam/templates/get", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def get_template():
    blocked = _license_blocked()
    if blocked:
        return blocked
    data = request.json or {}
    t = TemplateService.get_template_by_id(data.get('template_id'))
    if not t:
        return buildResponse({'status': 'failed', 'err': 'Not found'}, 200)
    return buildResponse(t, 200)

@app.route("/api/pam/templates/create", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def create_template():
    data = request.json or {}
    try:
        tdata = {
            'display_name': data.get('display_name', data.get('name', 'Custom Template')),
            'brand': data.get('brand', data.get('brand_id', 'generic')),
            'os_type': data.get('os_type', 'generic'),
            'connection': data.get('connection'),
            'prompt': data.get('prompt', data.get('prompt_pattern')),
            'privilege_escalation': data.get('privilege_escalation', data.get('privilege_escalation_cmd')),
            'commands': data.get('commands'),
            'pagination': data.get('pagination', data.get('pagination_disable_cmd')),
            'error_patterns': data.get('error_patterns', data.get('error_pattern')),
            'post_login_commands': data.get('post_login_commands'),
            'pre_logout_commands': data.get('pre_logout_commands'),
            'diff_exclusions': data.get('diff_exclusions'),
            'pre_connect': data.get('pre_connect'),
            'post_disconnect': data.get('post_disconnect'),
            'config_mode': data.get('config_mode'),
            'is_active': data.get('is_active', True),
        }
        tid = TemplateService.create_template(tdata)
        return buildResponse({'status': 'success', 'id': tid}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/templates/update", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def update_template():
    data = request.json or {}
    tid = data.get('id')
    try:
        if TemplateService.update_template(tid, data):
            return buildResponse({'status': 'success'}, 200)
        return buildResponse({'status': 'failed', 'err': 'Template not found'}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/templates/delete", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def delete_template():
    tid = (request.json or {}).get('id')
    template = DeviceTemplates.get_or_none(DeviceTemplates.id == tid)
    if not template:
        return buildResponse({'status': 'failed', 'err': 'Template not found'}, 200)
    if template.is_system:
        return buildResponse({'status': 'failed', 'err': 'System templates cannot be deleted'}, 200)
    dev_count = Devices.select().where(Devices.template_id == tid).count()
    if dev_count > 0:
        return buildResponse({'status': 'failed', 'err': f'Cannot delete: {dev_count} device(s) use this template'}, 200)
    if TemplateService.delete_template(tid):
        return buildResponse({'status': 'success'}, 200)
    return buildResponse({'status': 'failed', 'err': 'Cannot delete'}, 200)

# ==========================================
# Credentials
# ==========================================
@app.route("/api/pam/credentials/list", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def list_credentials():
    blocked = _license_blocked()
    if blocked:
        return blocked
    data = request.json or {}
    creds = CredentialService.list_credentials(
        scope=data.get('scope'),
        device_id=data.get('device_id'),
        group_id=data.get('group_id')
    )
    return buildResponse(creds, 200)

@app.route("/api/pam/credentials/create", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def create_credential():
    data = request.json or {}
    try:
        cid = CredentialService.create_credential(
            name=data['name'],
            credential_type=data['credential_type'],
            username=data['username'],
            plaintext_password=data['password'],
            scope=data['scope'],
            device_id=data.get('device_id'),
            group_id=data.get('group_id'),
            owner_id=request.user.id,
            auth_method=data.get('auth_method', 'password'),
            is_shared=data.get('is_shared', False),
            credential_group_id=data.get('credential_group_id')
        )
        return buildResponse({'status': 'success', 'id': cid}, 200)
    except Exception as e:
        log.error(f"create_credential error: {e}")
        return buildResponse({'status': 'failed', 'err': 'Error creating credential'}, 200)

@app.route("/api/pam/credentials/update", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def update_credential():
    data = request.json or {}
    try:
        cred = Credentials.get_by_id(data['id'])
        if 'name' in data: cred.name = data['name']
        if 'username' in data: cred.username = data['username']
        if 'device_id' in data: cred.device_id = data['device_id']
        if 'group_id' in data: cred.group_id = data['group_id']
        cred.modified = datetime.datetime.utcnow()
        cred.save()
        return buildResponse({'status': 'success'}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/credentials/rotate", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def rotate_credential():
    data = request.json or {}
    try:
        if CredentialService.rotate_credential(data['id'], data['new_password'], request.user.id):
            return buildResponse({'status': 'success'}, 200)
        return buildResponse({'status': 'failed', 'err': 'Credential not found'}, 200)
    except Exception as e:
        log.error(f"rotate_credential error: {e}")
        return buildResponse({'status': 'failed', 'err': 'Error rotating credential'}, 200)

@app.route("/api/pam/credentials/delete", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def delete_credential():
    cid = (request.json or {}).get('id')
    if CredentialService.delete_credential(cid):
        return buildResponse({'status': 'success'}, 200)
    return buildResponse({'status': 'failed', 'err': 'Not found'}, 200)

# ==========================================
# Device Connections
# ==========================================
@app.route("/api/pam/device-connections/list", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "read"})
def list_device_connections():
    blocked = _license_blocked()
    if blocked:
        return blocked
    dev_id = (request.json or {}).get('device_id')
    if not _user_can_access_device(request.user, dev_id):
        return buildResponse({"status": "failed", "error": "Access denied"}, 403)
    conns = list(DeviceConnections.select().where(DeviceConnections.device_id == dev_id).dicts())
    return buildResponse(conns, 200)

@app.route("/api/pam/device-connections/create", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def create_device_connection():
    data = request.json or {}
    try:
        now = datetime.datetime.utcnow()
        conn = DeviceConnections.create(
            device_id=data['device_id'],
            protocol=data['protocol'],
            port=data.get('port'),
            credential_id=data.get('credential_id'),
            privileged_credential_id=data.get('privileged_credential_id'),
            auth_mode=data.get('auth_mode', 'credential'),
            is_default=data.get('is_default', False),
            created=now,
            modified=now
        )
        return buildResponse({'status': 'success', 'id': conn.id}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/device-connections/update", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def update_device_connection():
    data = request.json or {}
    try:
        conn = DeviceConnections.get_by_id(data['id'])
        if 'port' in data: conn.port = data['port']
        if 'credential_id' in data: conn.credential_id = data['credential_id']
        if 'privileged_credential_id' in data: conn.privileged_credential_id = data['privileged_credential_id']
        if 'auth_mode' in data: conn.auth_mode = data['auth_mode']
        if 'is_default' in data: conn.is_default = data['is_default']
        if 'connection_type' in data: conn.connection_type = data['connection_type']
        conn.modified = datetime.datetime.utcnow()
        conn.save()
        return buildResponse({'status': 'success'}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@login_required(role="admin", perm={"pam_config": "full"})
@app.route("/api/pam/credential-mapping/set", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def set_credential_mapping():
    data = request.json or {}
    device_id = data.get('device_id')
    protocol = data.get('protocol')
    connection_type = data.get('connection_type', 'device')
    credential_id = data.get('credential_id')
    if not _user_can_access_device(request.user, device_id):
        return buildResponse({"status": "failed", "error": "Access denied"}, 403)
    if not device_id or not protocol:
        return buildResponse({'status': 'failed', 'err': 'device_id and protocol required'}, 200)
    valid_types = ('device', 'user', 'shared', 'override')
    if connection_type not in valid_types:
        return buildResponse({'status': 'failed', 'err': f'connection_type must be one of {valid_types}'}, 200)
    try:
        conn = DeviceConnections.get_or_none(
            DeviceConnections.device_id == device_id,
            DeviceConnections.protocol == protocol
        )
        if not conn:
            now = datetime.datetime.utcnow()
            conn = DeviceConnections.create(
                device_id=device_id, protocol=protocol,
                auth_mode='credential', connection_type=connection_type,
                credential_id=credential_id if connection_type == 'override' else None,
                created=now, modified=now
            )
        else:
            conn.connection_type = connection_type
            if connection_type == 'override':
                conn.credential_id = credential_id
            conn.modified = datetime.datetime.utcnow()
            conn.save()
        return buildResponse({'status': 'success', 'id': conn.id}, 200)
    except Exception as e:
        return buildResponse({'status': 'failed', 'err': str(e)}, 200)

@app.route("/api/pam/device-connections/delete", methods=["POST"])
@login_required(role="admin", perm={"pam_config": "full"})
def delete_device_connection():
    try:
        DeviceConnections.delete_by_id((request.json or {}).get('id'))
        return buildResponse({'status': 'success'}, 200)
    except:
        return buildResponse({'status': 'failed'}, 200)

# ==========================================
# Sessions
# ==========================================
@app.route("/api/pam/sessions/list", methods=["POST"])
@login_required(role="admin", perm={"pam_session": "read"})
def list_sessions():
    blocked = _license_blocked()
    if blocked:
        return blocked
    data = request.json or {}
    page = data.get('page', 1)
    limit = 50
    if request.user.role not in ('admin', 'superuser'):
        from libs.db.db_user_group_perm import DevUserGroupPermRel
        allowed = list(DevUserGroupPermRel.get_user_devices(request.user.id).dicts())
        dev_ids = [d['id'] for d in allowed]
        sessions = list(ConnectionSessions.select()
                       .where(ConnectionSessions.device_id.in_(dev_ids))
                       .order_by(ConnectionSessions.id.desc()).paginate(page, limit).dicts())
    else:
        sessions = list(ConnectionSessions.select().order_by(ConnectionSessions.id.desc()).paginate(page, limit).dicts())
    return buildResponse(sessions, 200)

@app.route("/api/pam/sessions/initiate", methods=["POST"])
@login_required(role="admin", perm={"pam_session": "write"})
def initiate_session():
    data = request.json or {}
    device_id = data.get('device_id')
    protocol = data.get('protocol')
    
    if not _user_can_access_device(request.user, device_id):
        return buildResponse({"status": "failed", "error": "Access denied"}, 403)
    
    try:
        dev = Devices.get_by_id(device_id)
        conn = DeviceConnections.get(DeviceConnections.device_id==device_id, DeviceConnections.protocol==protocol)
        
        # 1. Resolve Auth
        username, password = None, None
        if conn.auth_mode == 'credential':
            res = CredentialService.get_credential_for_connection(device_id, protocol)
            if res.get('method') == 'prompt':
                # Prompt fallback required
                if 'password' not in data:
                    return buildResponse({'status': 'prompt_required'}, 200)
                username = data.get('username')
                password = data.get('password')
            else:
                username = res['username']
                password = res['password']
        else:
            # Prompt mode strict
            if 'password' not in data:
                return buildResponse({'status': 'prompt_required'}, 200)
            username = data.get('username')
            password = data.get('password')

        # 2. Get Device Template
        t_dict = TemplateService.get_template_for_device(device_id)
        
        # 3. Handle Privilege Escalation
        enable_secret = None
        if conn.privileged_credential_id:
            from libs import kek_provider, envelope_crypto
            kek = kek_provider.get_kek()
            enable_secret = envelope_crypto.full_decrypt(
                conn.privileged_credential_id.encrypted_password,
                conn.privileged_credential_id.dek_encrypted,
                kek
            )
        # 4. DEPRECATED: Terminal sessions are now handled exclusively via PRO PAM.
        # Clients must use POST /api/terminal/init instead of this endpoint for SSH/Telnet.
        return buildResponse({"status": "failed", "error": "Endpoint deprecated. Use PRO PAM /api/terminal/init."}, 400)
    except Exception as e:
        log.error(f"initiate_session error: {e}")
        return buildResponse({'status': 'failed', 'err': 'Connection failed'}, 200)

@app.route("/api/pam/sessions/kill", methods=["POST"])
@login_required(role="admin", perm={"pam_session": "full"})
def kill_session():
    return buildResponse({'status': 'failed', 'error': 'Use PRO WebSocket to kill sessions.'}, 400)

@app.route("/api/pam/sessions/info", methods=["POST"])
@login_required(role="admin", perm={"pam_session": "read"})
def get_session_info():
    return buildResponse({'status': 'failed', 'error': 'Use PRO /api/terminal/sessions.'}, 400)
