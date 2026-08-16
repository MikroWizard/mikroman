#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# api_non_mikrotik.py: Non-MikroTik device management API

import datetime
import json
import logging
import ipaddress
from flask import Blueprint, request

from libs.webutil import app, buildResponse, login_required, get_myself, get_ip, get_agent
from libs.db import db_device, db_syslog, db_tasks
from libs.db.db_groups import DevGroupRel
from libs.db.db_pam import DeviceBrands, DeviceTemplates, DeviceConnections, Credentials
try:
    from libs.agent_validation import validate_agent_modes
except ImportError:
    def validate_agent_modes(agent_modes):
        return True, None
from libs import util, kek_provider, envelope_crypto
import bgtasks_non_mikrotik
try:
    from libs import utilpro
    ISPRO = True
except ImportError:
    ISPRO = False
    pass

log = logging.getLogger('api_non_mikrotik')
non_mikrotik_api = Blueprint('non_mikrotik_api', __name__)


def _template_supports_escalation(template_id):
    """True when the template defines a privilege escalation command.

    Returns True for unknown/missing template_id to preserve legacy behavior
    (the escalation credential is only meaningful when the template actually
    defines an escalation command; templates without one must never store one).
    """
    if not template_id:
        return True
    try:
        tpl = DeviceTemplates.get_or_none(DeviceTemplates.id == template_id)
        if not tpl:
            return True
        priv = tpl.privilege_escalation or {}
        return bool(isinstance(priv, dict) and priv.get("command"))
    except Exception as e:
        log.warning(f"_template_supports_escalation({template_id}) error: {e}")
        return True


@non_mikrotik_api.route('/api/non-mikrotik/devices/list', methods=['POST'])
@login_required(role="admin", perm={"device": "read"})
def list_non_mikrotik():
    user = get_myself()
    if user.role not in ('admin', 'superuser'):
        from libs.db.db_user_group_perm import DevUserGroupPermRel
        allowed = DevUserGroupPermRel.get_user_devices(user.id)
        devs = list(allowed.where(db_device.Devices.device_type != 'mikrotik').dicts())
    else:
        devs = list(db_device.Devices.select().where(db_device.Devices.device_type != 'mikrotik').dicts())
    for d in devs:
        d.pop('user_name', None)
        d.pop('password', None)
    return buildResponse({"status": "success", "data": devs})


@non_mikrotik_api.route('/api/non-mikrotik/devices/info', methods=['POST'])
@login_required(role="admin", perm={"device": "read"})
def get_non_mikrotik():
    devid = (request.json or {}).get('device_id')
    if not devid:
        return buildResponse({"status": "failed", "error": "device_id required"}, 400)
    dev = db_device.get_device(devid)
    if not dev:
        return buildResponse({"status": "failed", "error": "Device not found"}, 404)
    
    # Fetch connection types
    from libs.db.db_pam import DeviceConnections, Credentials
    conns = list(DeviceConnections.select().where(DeviceConnections.device_id == devid))
    dev["connection_types"] = [c.protocol for c in conns]
    
    default_conn = next((c for c in conns if c.is_default), None) or (conns[0] if conns else None)
    if default_conn:
        dev["protocol"] = default_conn.protocol
        dev["port"] = default_conn.port
        dev["agent_modes"] = default_conn.agent_modes
    
    # Fetch the primary (login) credential — exclude the enable/escalation credential
    cred = Credentials.select().where(
        Credentials.device_id == devid,
        Credentials.scope == 'device',
        Credentials.credential_type != 'enable'
    ).order_by(Credentials.id.desc()).first()
    if cred:
        dev["username"] = cred.username or ''
        dev["ssh_auth_mode"] = 'key' if cred.auth_method == 'key' else 'credential'
    else:
        dev["username"] = ''
        dev["ssh_auth_mode"] = 'credential'

    # Detect whether an enable/escalation credential is configured
    enable_cred = Credentials.select().where(
        Credentials.device_id == devid,
        Credentials.scope == 'device',
        Credentials.credential_type == 'enable'
    ).first()
    dev["has_enable"] = bool(enable_cred)
    
    dev.pop('user_name', None)
    dev.pop('password', None)
        
    return buildResponse({"status": "success", "data": dev})


@non_mikrotik_api.route('/api/non-mikrotik/devices/add', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def add_non_mikrotik():
    """Add a single non-MikroTik device with full PAM setup."""
    user = get_myself()
    data = request.json or {}
    ip = data.get('ip', '').strip()
    name = data.get('name', 'Unknown Device')
    mac = data.get('mac', '')
    device_type = data.get('device_type', 'generic')
    device_model = data.get('device_model', '')
    template_id = data.get('template_id')
    username = data.get('username', '')
    password = data.get('password', '')
    enable_password = data.get('enable_password', '')
    protocol = data.get('protocol', 'ssh')
    port = data.get('port', None)
    group_ids = data.get('group_ids', [])
    if not ip:
        return buildResponse({"status": "failed", "error": "IP required"}, 400)
    if db_device.query_device_by_ip(ip):
        return buildResponse({"status": "failed", "error": "IP already exists"}, 200)
    if ISPRO:
        try:
            allowed, err = utilpro.can_add_device('other')
            if not allowed:
                return buildResponse({"status": "failed", "error": err}, 200)
        except Exception as e:
            log.error(e)
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        enc_user = util.crypt_data(username) if username else ''
        enc_pass = util.crypt_data(password) if password else ''
        new_dev = db_device.Devices.create(
            name=name, ip=ip, mac=mac, details="{}", uptime="", license="", interface="",
            user_name=enc_user, password=enc_pass, port="",
            update_availble=False, current_firmware="", arch="", sensors="",
            router_type="", wifi_config="", upgrade_avail=False,
            owner=user, created=now, modified=now, peer_ip=util.resolve_peer_ip({"ip": ip}), failed_attempt=0,
            status="active", firmware_to_install="", syslog_configured=False, upgrade_device=False,
            device_type=device_type, device_model=device_model, template_id=template_id
        )
        from libs.db.db_pam import DeviceConnections, Credentials
        port_map = {'ssh': 22, 'telnet': 23, 'web': 80, 'api': 8728}
        resolved_port = int(port) if port else port_map.get(protocol, 22)
        agent_modes = data.get('agent_modes') if protocol == 'ssh' else None
        if isinstance(agent_modes, dict):
            valid, err = validate_agent_modes(agent_modes)
            if not valid:
                return buildResponse({"status": "failed", "error": err}, 400)
        DeviceConnections.create(
            device_id=new_dev.id, protocol=protocol, port=resolved_port,
            auth_mode='credential', is_default=True,
            created=now, modified=now,
            agent_modes=agent_modes
        )
        if username and password:
            kek = kek_provider.get_kek()
            enc_bundle = envelope_crypto.full_encrypt(password, kek)
            auth_method = data.get('ssh_auth_mode', 'credential')
            
            cred_kwargs = {
                'name': f"Device {new_dev.id} Primary", 'credential_type': protocol,
                'username': username,
                'dek_encrypted': enc_bundle['dek_encrypted'],
                'auth_method': auth_method, 'scope': 'device',
                'device_id': new_dev.id, 'owner_id': user.id,
                'created': now, 'modified': now
            }
            if auth_method == 'key':
                cred_kwargs['encrypted_private_key'] = enc_bundle['encrypted_payload']
            else:
                cred_kwargs['encrypted_password'] = enc_bundle['encrypted_payload']
                
            new_cred = Credentials.create(**cred_kwargs)
            
            default_conn = DeviceConnections.get(DeviceConnections.device_id == new_dev.id, DeviceConnections.is_default == True)
            default_conn.credential_id = new_cred.id
            default_conn.save()
        if enable_password and _template_supports_escalation(template_id):
            kek = kek_provider.get_kek()
            enable_enc = envelope_crypto.full_encrypt(enable_password, kek)
            priv_cred = Credentials.create(
                name=f"Device {new_dev.id} Enable", credential_type='enable',
                username='',
                encrypted_password=enable_enc['encrypted_payload'],
                dek_encrypted=enable_enc['dek_encrypted'],
                auth_method='password', scope='device',
                device_id=new_dev.id, owner_id=user.id,
                created=now, modified=now
            )
            default_conn = DeviceConnections.get(DeviceConnections.device_id == new_dev.id, DeviceConnections.is_default == True)
            default_conn.privileged_credential_id = priv_cred.id
            default_conn.save()
        for gid in group_ids:
            try:
                DevGroupRel.create(group_id=gid, device_id=new_dev.id)
            except Exception:
                pass
        db_syslog.add_syslog_event(user, "Device", "Create", get_ip(), get_agent(), json.dumps(data))
        return buildResponse({"status": "success", "id": new_dev.id})
    except Exception as e:
        log.error(f"add_non_mikrotik error: {e}")
        return buildResponse({"status": "failed", "error": str(e)}, 200)


@non_mikrotik_api.route('/api/non-mikrotik/devices/edit', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def edit_non_mikrotik():
    """Edit non-MikroTik device fields including template, type, credentials."""
    user = get_myself()
    data = request.json or {}
    devid = data.get('id')
    if not devid:
        return buildResponse({"status": "failed", "error": "id required"}, 400)
    try:
        update_fields = {}
        for field in ('name', 'ip', 'mac', 'device_type', 'device_model', 'template_id', 'port'):
            if field in data and data[field] is not None:
                update_fields[field] = data[field]
        if 'username' in data:
            update_fields['user_name'] = util.crypt_data(data['username'])
        if data.get('password') and data['password'] not in (None, '', 'Password is Hidden'):
            update_fields['password'] = util.crypt_data(data['password'])
        if update_fields:
            db_device.Devices.update(update_fields).where(db_device.Devices.id == devid).execute()
        if data.get('password') and data['password'] not in (None, '', 'Password is Hidden'):
            kek = kek_provider.get_kek()
            enc_bundle = envelope_crypto.full_encrypt(data['password'], kek)
            creds = list(Credentials.select().where(
                Credentials.device_id == devid,
                Credentials.scope == 'device',
                Credentials.credential_type != 'enable'
            ))
            auth_method = data.get('ssh_auth_mode', 'credential')
            if creds:
                for cred in creds:
                    cred.dek_encrypted = enc_bundle['dek_encrypted']
                    cred.auth_method = auth_method
                    if data.get('protocol'):
                        cred.credential_type = data['protocol']
                    if auth_method == 'key':
                        cred.encrypted_private_key = enc_bundle['encrypted_payload']
                        cred.encrypted_password = None
                    else:
                        cred.encrypted_password = enc_bundle['encrypted_payload']
                        cred.encrypted_private_key = None
                    cred.save()
            else:
                credential_type = data.get('protocol', 'ssh')
                cred_kwargs = {
                    'name': f"Device {devid} Primary", 'credential_type': credential_type,
                    'username': data.get('username', ''),
                    'dek_encrypted': enc_bundle['dek_encrypted'],
                    'auth_method': auth_method, 'scope': 'device',
                    'device_id': devid, 'owner_id': user.id,
                    'created': datetime.datetime.now(datetime.timezone.utc),
                    'modified': datetime.datetime.now(datetime.timezone.utc)
                }
                if auth_method == 'key':
                    cred_kwargs['encrypted_private_key'] = enc_bundle['encrypted_payload']
                else:
                    cred_kwargs['encrypted_password'] = enc_bundle['encrypted_payload']
                Credentials.create(**cred_kwargs)

        # Sync username on the primary (login) credential when username is updated
        if data.get('username') is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
            for cred in Credentials.select().where(
                Credentials.device_id == devid,
                Credentials.scope == 'device',
                Credentials.credential_type != 'enable'
            ):
                if cred.username != data['username']:
                    cred.username = data['username']
                    cred.modified = now
                    cred.save()

        # Link the primary credential to the default connection when it was
        # never linked (e.g. device created without credentials then edited).
        try:
            default_conn = DeviceConnections.get_or_none(
                DeviceConnections.device_id == devid,
                DeviceConnections.is_default == True
            )
            if default_conn and not default_conn.credential_id:
                primary = Credentials.select().where(
                    Credentials.device_id == devid,
                    Credentials.scope == 'device',
                    Credentials.credential_type != 'enable'
                ).order_by(Credentials.id.desc()).first()
                if primary:
                    default_conn.credential_id = primary.id
                    default_conn.save()
        except Exception as e:
            log.error(f"Failed to link credential to connection: {e}")

        # Handle enable/escalation password
        enable_password = data.get('enable_password')
        if data.get('clear_enable_password'):
            # Explicitly remove a stale escalation credential (e.g. a previously
            # auto-filled value the user never intended).
            default_conn = DeviceConnections.get_or_none(
                DeviceConnections.device_id == devid,
                DeviceConnections.is_default == True
            )
            if default_conn and default_conn.privileged_credential_id:
                try:
                    Credentials.delete().where(
                        Credentials.id == default_conn.privileged_credential_id
                    ).execute()
                except Exception as e:
                    log.error(f"Failed to delete stale enable credential for device {devid}: {e}")
                default_conn.privileged_credential_id = None
                default_conn.save()
        elif enable_password and enable_password not in (None, ''):
            now = datetime.datetime.now(datetime.timezone.utc)
            if not _template_supports_escalation(data.get('template_id')):
                enable_password = None
            if enable_password:
                kek = kek_provider.get_kek()
                enable_enc = envelope_crypto.full_encrypt(enable_password, kek)
                default_conn = DeviceConnections.get_or_none(
                    DeviceConnections.device_id == devid,
                    DeviceConnections.is_default == True
                )
                enable_cred = None
                if default_conn and default_conn.privileged_credential_id:
                    enable_cred = Credentials.get_or_none(
                        Credentials.id == default_conn.privileged_credential_id
                    )
                if enable_cred:
                    enable_cred.encrypted_password = enable_enc['encrypted_payload']
                    enable_cred.dek_encrypted = enable_enc['dek_encrypted']
                    enable_cred.modified = now
                    enable_cred.save()
                else:
                    enable_cred = Credentials.create(
                        name=f"Device {devid} Enable", credential_type='enable',
                        username='',
                        encrypted_password=enable_enc['encrypted_payload'],
                        dek_encrypted=enable_enc['dek_encrypted'],
                        auth_method='password', scope='device',
                        device_id=devid, owner_id=user.id,
                        created=now, modified=now
                    )
                    if default_conn:
                        default_conn.privileged_credential_id = enable_cred.id
                        default_conn.save()

        if 'protocol' in data or 'port' in data:
            now = datetime.datetime.now(datetime.timezone.utc)
            port_map = {'ssh': 22, 'telnet': 23, 'web': 80, 'api': 8728}
            
            proto = data.get('protocol') or 'ssh'
            resolved_port = int(data.get('port')) if data.get('port') else port_map.get(proto, 22)
            
            log.info(f"edit_non_mikrotik: devid={devid}, setting protocol={proto}, port={resolved_port}")
            
            existing = DeviceConnections.get_or_none(
                DeviceConnections.device_id == devid,
                DeviceConnections.is_default == True
            )
            if existing:
                log.info(f"edit_non_mikrotik: updating existing connection id={existing.id} from {existing.protocol}:{existing.port} to {proto}:{resolved_port}")
                existing.protocol = proto
                existing.port = resolved_port
                existing.modified = now
                existing.save()
            else:
                log.info(f"edit_non_mikrotik: creating new connection {proto}:{resolved_port}")
                DeviceConnections.create(
                    device_id=devid, protocol=proto, port=resolved_port,
                    auth_mode='credential', is_default=True,
                    created=now, modified=now
                )
                
        db_syslog.add_syslog_event(user, "Device", "Edit", get_ip(), get_agent(), json.dumps(data))
        return buildResponse({"status": "success"})
    except Exception as e:
        log.error(f"edit_non_mikrotik error: {e}")
        return buildResponse({"status": "failed", "error": str(e)}, 200)


@non_mikrotik_api.route('/api/non-mikrotik/devices/delete', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def delete_non_mikrotik():
    user = get_myself()
    data = request.json or {}
    devid = data.get('id')
    if not devid:
        return buildResponse({"status": "failed", "error": "id required"}, 400)
    try:
        from libs.db import db_groups
        if db_groups.delete_device(devid):
            db_syslog.add_syslog_event(user, "Device", "Delete", get_ip(), get_agent(), json.dumps(data))
            return buildResponse({"status": "success"})
        return buildResponse({"status": "failed", "error": "Unable to delete device"}, 200)
    except Exception as e:
        log.error(f"delete_non_mikrotik error: {e}")
        return buildResponse({"status": "failed", "error": str(e)}, 200)


@non_mikrotik_api.route('/api/non-mikrotik/groups/attach', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def attach_to_groups():
    user = get_myself()
    data = request.json or {}
    devid = data.get('device_id')
    group_ids = data.get('group_ids', [])
    if not devid or not group_ids:
        return buildResponse({"status": "failed", "error": "device_id and group_ids required"}, 400)
    for gid in group_ids:
        DevGroupRel.get_or_create(group_id=gid, device_id=devid, defaults={'group_id': gid, 'device_id': devid})
    return buildResponse({"status": "success"})

# ==========================================
# Bulk Add — validation & execution
# ==========================================

PORT_MAP = {'ssh': 22, 'telnet': 23, 'web': 80, 'api': 8728}


def _validate_device_row(device_info, index, brands_set, templates_map):
    """Validate a single non-MikroTik device row. Returns (valid, errors, warnings)."""
    errors = []
    warnings = []
    ip = device_info.get('ip', '').strip()

    if not ip:
        errors.append("Missing IP address")
    else:
        try:
            ipaddress.IPv4Address(ip)
        except:
            errors.append("Invalid IP address format")

    if not device_info.get('username'):
        errors.append("Missing username")
    if not device_info.get('password'):
        errors.append("Missing password")

    device_type = device_info.get('device_type', '').strip()
    if not device_type:
        errors.append("Missing device_type/brand")
    elif device_type not in brands_set:
        errors.append(f"Unknown device_type '{device_type}' — see brand guide")

    protocol = device_info.get('protocol', 'ssh').strip()
    if protocol not in ('ssh', 'telnet'):
        errors.append(f"Invalid protocol '{protocol}' — must be 'ssh' or 'telnet'")
    device_info['protocol'] = protocol

    port = device_info.get('port')
    if port:
        try:
            port = int(port)
            if port < 1 or port > 65535:
                errors.append(f"Port must be 1-65535, got {port}")
            device_info['port'] = port
        except (ValueError, TypeError):
            errors.append(f"Invalid port '{port}' — must be a number")

    template_id = device_info.get('template_id')
    if template_id:
        template_id = int(template_id) if str(template_id).isdigit() else template_id
    else:
        template_id_str = device_info.get('template_id_str', device_info.get('template_id'))
        if template_id_str and str(template_id_str).strip().isdigit():
            template_id = int(str(template_id_str).strip())

    if not template_id:
        errors.append("Missing template_id — a connection template is required")
    elif template_id:
        template = templates_map.get(int(template_id)) if isinstance(template_id, int) else templates_map.get(str(template_id))
        if not template:
            template = DeviceTemplates.get_or_none(DeviceTemplates.id == int(template_id))
            if template:
                template = {
                    'id': template.id,
                    'brand': template.brand,
                    'display_name': template.display_name,
                    'connection': template.connection or {},
                    'privilege_escalation': template.privilege_escalation,
                }

        if not template:
            errors.append(f"Template ID {template_id} not found")
        else:
            if template.get('brand') and template['brand'] != device_type:
                errors.append(f"Template '{template.get('display_name')}' is for brand '{template['brand']}', not '{device_type}'")

            tmpl_protos = (template.get('connection') or {}).get('protocols', [])
            if tmpl_protos:
                if protocol not in tmpl_protos:
                    errors.append(f"Template '{template.get('display_name')}' does not support protocol '{protocol}' (supports: {', '.join(tmpl_protos)})")

            priv_esc = template.get('privilege_escalation')
            has_privilege_escalation = bool(isinstance(priv_esc, dict) and priv_esc.get('command'))
            enable_provided = bool(device_info.get('enable_password'))
            if has_privilege_escalation and not enable_provided:
                errors.append(f"Template '{template.get('display_name')}' requires enable_password")
            elif enable_provided and not has_privilege_escalation:
                warnings.append(f"enable_password provided but template '{template.get('display_name')}' does not use it")

    # Check duplicate IP only if IP is valid
    if ip:
        try:
            ipaddress.IPv4Address(ip)
            if db_device.query_device_by_ip(ip):
                warnings.append(f"IP {ip} already exists in database — will be skipped")
        except:
            pass

    valid = len(errors) == 0
    return {
        'index': index,
        'valid': valid,
        'ip': ip,
        'errors': errors,
        'warnings': warnings,
        'device_type': device_type
    }


@non_mikrotik_api.route('/api/non-mikrotik/devices/bulk/validate', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def validate_non_mikrotik_bulk():
    """Validate non-MikroTik devices without inserting. Returns per-row status + catalog data."""
    data = request.json or {}
    devices = data.get('devices', [])

    if not devices or not isinstance(devices, list):
        return buildResponse({"status": "failed", "error": "devices array required"}, 400)

    # Load brand + template catalog for guide
    brands = list(DeviceBrands.select().where(DeviceBrands.is_active == True).dicts())
    brands_set = set(b['brand'] for b in brands)

    templates_raw = list(DeviceTemplates.select().where(DeviceTemplates.is_active == True).dicts())
    templates_map = {}
    for t in templates_raw:
        tid = t.get('id')
        if tid:
            templates_map[tid] = t
            templates_map[str(tid)] = t

    guide_templates = []
    for t in templates_raw:
        tmpl_protos = (t.get('connection') or {}).get('protocols', [])
        guide_templates.append({
            'id': t['id'],
            'brand': t.get('brand'),
            'display_name': t.get('display_name'),
            'os_type': t.get('os_type'),
            'protocols': tmpl_protos,
            'has_enable': bool(t.get('privilege_escalation')),
        })

    guide_brands = [b for b in brands if b.get('brand') != 'mikrotik']

    rows = []
    any_errors = False
    any_warnings = False
    for idx, dev in enumerate(devices):
        row = _validate_device_row(dev, idx, brands_set, templates_map)
        rows.append(row)
        if not row['valid']:
            any_errors = True
        if row['warnings']:
            any_warnings = True

    return buildResponse({
        'status': 'success',
        'valid': not any_errors,
        'has_warnings': any_warnings,
        'rows': rows,
        'brands': guide_brands,
        'templates': guide_templates
    }, 200)


@non_mikrotik_api.route('/api/non-mikrotik/devices/bulk_add', methods=['POST'])
@login_required(role="admin", perm={"device": "full"})
def bulk_add_non_mikrotik():
    """Bulk add non-MikroTik devices. Validates first, then creates task."""
    user = get_myself()
    input_data = request.json or {}
    devices = input_data.get('devices', [])

    if not devices or not isinstance(devices, list):
        return buildResponse({'error': 'Invalid device data provided'}, 400)

    # Load brands + templates for validation
    brands = list(DeviceBrands.select().where(DeviceBrands.is_active == True).dicts())
    brands_set = set(b['brand'] for b in brands)

    templates_raw = list(DeviceTemplates.select().where(DeviceTemplates.is_active == True).dicts())
    templates_map = {}
    for t in templates_raw:
        tid = t.get('id')
        if tid:
            templates_map[tid] = t
            templates_map[str(tid)] = t

    # Validate all rows first
    rows = []
    any_errors = False
    for idx, dev in enumerate(devices):
        row = _validate_device_row(dev, idx, brands_set, templates_map)
        rows.append(row)
        if not row['valid']:
            any_errors = True

    if any_errors:
        return buildResponse({
            'status': 'validation_failed',
            'rows': rows
        }, 200)

    # Enforce the non-MikroTik device limit before creating the task
    if ISPRO:
        try:
            status = utilpro.check_license_status()
            if status['reason'] in ('invalid', 'expired'):
                return buildResponse({"status": "failed", "error": "License is not valid. Please renew your license."}, 200)
            counts = status['counts']
            limits = status['limits']
            if counts['other'] + len(devices) > limits['other']:
                return buildResponse({"status": "failed", "error": "Non-MikroTik device limit reached ({} of {}). Delete devices or renew your license.".format(counts['other'], limits['other'])}, 200)
        except Exception as e:
            log.error(e)

    # Prepare clean device list for background task
    clean_devices = []
    for idx, dev in enumerate(devices):
        template_id = dev.get('template_id')
        if template_id:
            try:
                template_id = int(template_id)
            except (ValueError, TypeError):
                template_id = None

        group_ids = dev.get('group_ids')
        if isinstance(group_ids, str):
            group_ids = [int(g.strip()) for g in group_ids.replace('+', ',').split(',') if g.strip().isdigit()]
        elif not isinstance(group_ids, list):
            group_ids = []

        clean_devices.append({
            'ip': dev.get('ip', '').strip(),
            'name': dev.get('name', '').strip() or None,
            'device_type': dev.get('device_type', '').strip(),
            'device_model': dev.get('device_model', '').strip() or '',
            'template_id': template_id,
            'username': dev.get('username', ''),
            'password': dev.get('password', ''),
            'enable_password': dev.get('enable_password', ''),
            'protocol': dev.get('protocol', 'ssh'),
            'port': dev.get('port'),
            'group_ids': group_ids,
            'mac': dev.get('mac', '').strip() or '',
            'ssh_auth_mode': dev.get('ssh_auth_mode', 'credential'),
            'agent_modes': dev.get('agent_modes'),
        })

    now = datetime.datetime.now(datetime.timezone.utc)
    task_id = f"bulk_add_nonmikrotik_{now.strftime('%Y%m%d_%H%M%S')}_{hash(str(devices)) % 1000000}"

    db_tasks.create_bulk_add_task(task_id)
    db_syslog.add_syslog_event(user, "Bulk Add (Non-MikroTik)", "start", get_ip(), get_agent(), json.dumps(input_data))

    bgtasks_non_mikrotik.bulk_add_non_mikrotik_devices(
        devices=clean_devices,
        user_id=user.id,
        task_id=task_id
    )

    return buildResponse({'taskId': task_id}, 200)


app.register_blueprint(non_mikrotik_api)
