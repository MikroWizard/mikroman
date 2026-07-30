#!/usr/bin/python
# -*- coding: utf-8 -*-

# bgtasks_non_mikrotik.py: background tasks for non-MikroTik bulk device operations
# MikroWizard.com

from uwsgidecorators import spool
import datetime
import json
import logging
import ipaddress

from libs.db import db_tasks, db_syslog, db_device
from libs import util, kek_provider, envelope_crypto
from libs.db.db_device import Devices
from libs.db.db_groups import DevGroupRel
from libs.db.db_pam import DeviceConnections, Credentials, DeviceTemplates
from libs.agent_validation import validate_agent_modes
from libs.webutil import get_myself, get_ip, get_agent

log = logging.getLogger("bgtasks_non_mikrotik")

def serialize_datetime(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    return str(obj)

PORT_MAP = {'ssh': 22, 'telnet': 23, 'web': 80, 'api': 8728}

@spool(pass_arguments=True)
def bulk_add_non_mikrotik_devices(*args, **kwargs):
    try:
        task_id = kwargs.get('task_id', '')
        task = db_tasks.get_bulk_add_task(task_id)
        if not task:
            return False
        if task.action == 'cancel':
            task.status = 0
            task.save()
            return False
        task.status = 1
        task.save()

        devices = kwargs.get('devices', [])
        user_id = kwargs.get('user_id')
        now = datetime.datetime.now(datetime.timezone.utc)

        results = []
        inserted_ids = []

        for idx, device_info in enumerate(devices):
            ip = device_info.get('ip', '').strip()
            result = {'ip': ip, 'added': False, 'failures': ''}

            try:
                ipaddress.IPv4Address(ip)
            except:
                result['failures'] = "Invalid IP address"
                results.append(result)
                continue

            if db_device.query_device_by_ip(ip):
                result['added'] = False
                result['failures'] = "IP already exists"
                results.append(result)
                continue

            name = device_info.get('name') or ip
            device_type = device_info.get('device_type', 'generic')
            device_model = device_info.get('device_model', '')
            template_id = device_info.get('template_id')
            username = device_info.get('username', '')
            password = device_info.get('password', '')
            enable_password = device_info.get('enable_password', '')
            protocol = device_info.get('protocol', 'ssh')
            group_ids = device_info.get('group_ids', [])
            mac = device_info.get('mac', '')
            ssh_auth_mode = device_info.get('ssh_auth_mode', 'credential')
            agent_modes = device_info.get('agent_modes')

            try:
                enc_user = util.crypt_data(username) if username else ''
                enc_pass = util.crypt_data(password) if password else ''

                new_dev = Devices.create(
                    name=name, ip=ip, mac=mac, details="{}", uptime="", license="", interface="",
                    user_name=enc_user, password=enc_pass, port="",
                    update_availble=False, current_firmware="", arch="", sensors="",
                    router_type="", wifi_config="", upgrade_avail=False,
                    owner=user_id, created=now, modified=now, peer_ip="", failed_attempt=0,
                    status="active", firmware_to_install="", syslog_configured=False, upgrade_device=False,
                    device_type=device_type, device_model=device_model, template_id=template_id
                )
                inserted_ids.append(new_dev.id)

                resolved_port = int(device_info.get('port')) if device_info.get('port') else PORT_MAP.get(protocol, 22)
                am = agent_modes if protocol == 'ssh' else None
                if isinstance(am, dict):
                    valid, err = validate_agent_modes(am)
                    if not valid:
                        result['failures'] = err
                        results.append(result)
                        continue
                DeviceConnections.create(
                    device_id=new_dev.id, protocol=protocol, port=resolved_port,
                    auth_mode='credential', is_default=True,
                    created=now, modified=now, agent_modes=am
                )

                if username and password:
                    kek = kek_provider.get_kek()
                    enc_bundle = envelope_crypto.full_encrypt(password, kek)
                    cred_kwargs = {
                        'name': f"Device {new_dev.id} Primary", 'credential_type': protocol,
                        'username': username,
                        'dek_encrypted': enc_bundle['dek_encrypted'],
                        'auth_method': ssh_auth_mode, 'scope': 'device',
                        'device_id': new_dev.id, 'owner_id': user_id,
                        'created': now, 'modified': now
                    }
                    if ssh_auth_mode == 'key':
                        cred_kwargs['encrypted_private_key'] = enc_bundle['encrypted_payload']
                    else:
                        cred_kwargs['encrypted_password'] = enc_bundle['encrypted_payload']
                    new_cred = Credentials.create(**cred_kwargs)
                    default_conn = DeviceConnections.get(DeviceConnections.device_id == new_dev.id, DeviceConnections.is_default == True)
                    default_conn.credential_id = new_cred.id
                    default_conn.save()

                if enable_password:
                    kek = kek_provider.get_kek()
                    enable_enc = envelope_crypto.full_encrypt(enable_password, kek)
                    priv_cred = Credentials.create(
                        name=f"Device {new_dev.id} Enable", credential_type='enable',
                        username='',
                        encrypted_password=enable_enc['encrypted_payload'],
                        dek_encrypted=enable_enc['dek_encrypted'],
                        auth_method='password', scope='device',
                        device_id=new_dev.id, owner_id=user_id,
                        created=now, modified=now
                    )
                    try:
                        default_conn = DeviceConnections.get(
                            DeviceConnections.device_id == new_dev.id,
                            DeviceConnections.is_default == True
                        )
                        default_conn.privileged_credential_id = priv_cred.id
                        default_conn.save()
                    except DeviceConnections.DoesNotExist:
                        pass

                for gid in group_ids:
                    try:
                        DevGroupRel.create(group_id=gid, device_id=new_dev.id)
                    except Exception:
                        pass

                result['added'] = True

            except Exception as e:
                result['failures'] = str(e)
                log.error(f"Error inserting non-MikroTik device {ip}: {e}")

            results.append(result)

        info = {
            'task_id': task_id,
            'user_id': user_id,
            'device_count': len(devices),
            'created': now.strftime("%Y-%m-%dT%H:%M:%S")
        }

        try:
            db_tasks.add_task_result('bulk-add', json.dumps(results, default=serialize_datetime), json.dumps(info, default=serialize_datetime))
        except Exception as e:
            log.error(f"Error saving bulk add results: {e}")

        task.status = 0
        task.save()
        return True

    except Exception as e:
        log.error(f"bulk_add_non_mikrotik_devices error: {e}")
        if 'task' in locals():
            task.status = 0
            task.save()
        return False
