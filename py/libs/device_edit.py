#!/usr/bin/python
# -*- coding: utf-8 -*-

# device_edit.py: device settings edit shared by the single-device edit form and the bulk edit
# (MikroWizard records, optionally also the router's /ip service ports), and the records every
# newly added device gets (default PAM credentials, the device groups chosen in the add form)
# MikroWizard.com , Mikrotik router management solution

import datetime
import logging

from libs import envelope_crypto, kek_provider, util
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.db import db_device
from libs.db.db import database
from libs.db.db_groups import DevGroupRel, DevGroups
from libs.db.db_pam import Credentials, DeviceConnections

log = logging.getLogger("device_edit")

API_PORT, API_SSL_PORT, SSH_PORT = 8728, 8729, 22
ROUTER_TIMEOUT = 5


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def sync_device_credentials(dev):
    """Copy the device user / password (devices row) to its device-scoped PAM credentials;
    create the default ones when the device has none."""
    dec_user = util.decrypt_data(dev.user_name) if dev.user_name else ""
    dec_pass = util.decrypt_data(dev.password) if dev.password else ""
    creds = list(Credentials.select().where(Credentials.device_id == dev.id, Credentials.scope == 'device'))
    enc_bundle = envelope_crypto.full_encrypt(dec_pass, kek_provider.get_kek())
    if creds:
        for cred in creds:
            cred.username = dec_user
            cred.encrypted_password = enc_bundle['encrypted_payload']
            cred.dek_encrypted = enc_bundle['dek_encrypted']
            cred.modified = _now()
            cred.save()
        return
    _create_default_credentials(dev, dec_user, enc_bundle)


def ensure_device_credentials(dev):
    """Default device-scoped PAM credentials for a newly added device (the same ones the edit
    form creates). A device that already has device-scoped credentials is left as it is.
    Returns True when credentials were created."""
    if Credentials.select().where(Credentials.device_id == dev.id, Credentials.scope == 'device').exists():
        return False
    dec_user = util.decrypt_data(dev.user_name) if dev.user_name else ""
    dec_pass = util.decrypt_data(dev.password) if dev.password else ""
    _create_default_credentials(dev, dec_user, envelope_crypto.full_encrypt(dec_pass, kek_provider.get_kek()))
    return True


def _create_default_credentials(dev, dec_user, enc_bundle):
    is_mikrotik = getattr(dev, 'device_type', 'mikrotik') == 'mikrotik'
    for t in (["webfig", "ssh"] if is_mikrotik else ["ssh"]):
        Credentials.create(
            name=f"Device {dev.id} {t.upper()} Credential",
            credential_type=t,
            username=dec_user,
            encrypted_password=enc_bundle['encrypted_payload'],
            dek_encrypted=enc_bundle['dek_encrypted'],
            auth_method="password",
            scope="device",
            device_id=dev.id,
            owner_id=dev.owner,
            created=_now(),
            modified=_now(),
        )


def parse_group_ids(value):
    """Group ids from a list or a text such as "2,5" / "2+5" (CSV import); other values ignored."""
    if value is None or value is False:
        return []
    items = value if isinstance(value, (list, tuple, set)) else str(value).replace('+', ',').split(',')
    out = []
    for item in items:
        try:
            gid = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if gid > 0 and gid not in out:
            out.append(gid)
    return out


def assign_groups(device_ids, group_ids=None):
    """Add devices to the given groups (groups that exist). Only adds memberships, never removes
    one; never raises (logged). The default group (id 1) means all devices without a membership
    row (db_groups / db_user_group_perm), so it needs none."""
    try:
        ids = [int(d) for d in device_ids if d]
        wanted = set(parse_group_ids(group_ids))
        if not ids or not wanted:
            return
        with database.atomic():
            groups = [g.id for g in DevGroups.select(DevGroups.id).where(DevGroups.id << list(wanted))]
            if not groups:
                return
            have = set(DevGroupRel.select(DevGroupRel.group_id, DevGroupRel.device_id)
                       .where((DevGroupRel.device_id << ids) & (DevGroupRel.group_id << groups)).tuples())
            rows = [{'group_id': g, 'device_id': d} for g in groups for d in ids if (g, d) not in have]
            if rows:
                DevGroupRel.insert_many(rows).execute()
    except Exception as e:
        log.error("device groups not assigned (devices %s): %s", device_ids, e)


def sync_api_connection(devid, port, ssl):
    """Keep the device's 'api' connection row (port + ssl) equal to the devices row."""
    resolved_port = int(port) if port else (API_SSL_PORT if ssl else API_PORT)
    api_conn = DeviceConnections.get_or_none(DeviceConnections.device_id == devid, DeviceConnections.protocol == 'api')
    if api_conn:
        api_conn.port = resolved_port
        api_conn.ssl = bool(ssl)
        api_conn.modified = _now()
        api_conn.save()


def set_ssh_port(devid, port):
    """Port of the device's SSH connection row (created like add_device does when missing)."""
    conn = DeviceConnections.get_or_none(DeviceConnections.device_id == devid, DeviceConnections.protocol == 'ssh')
    if conn:
        conn.port = int(port)
        conn.modified = _now()
        conn.save()
    else:
        DeviceConnections.create(device_id=devid, protocol='ssh', port=int(port), auth_mode='credential',
                                 is_default=False, created=_now(), modified=_now())


def current_ssh_port(devid):
    conn = DeviceConnections.get_or_none(DeviceConnections.device_id == devid, DeviceConnections.protocol == 'ssh')
    return int(conn.port) if conn and conn.port else SSH_PORT


def is_mikrotik(dev):
    return (getattr(dev, 'device_type', None) or 'mikrotik').lower() == 'mikrotik'


def plan_changes(dev, changes):
    """The new values for one device: only the fields given in `changes` change.
    Returns dict(ssl, api_port, ssh_port, user_name, password) with old and new values."""
    old_ssl = bool(getattr(dev, 'ssl', False))
    old_port = util.get_device_port(dev)
    new_ssl = bool(changes['ssl']) if 'ssl' in changes else old_ssl
    if 'api_port' in changes:
        new_port = int(changes['api_port'])
    elif new_ssl != old_ssl and old_port in (API_PORT, API_SSL_PORT):
        new_port = API_SSL_PORT if new_ssl else API_PORT      # default port of the other mode
    else:
        new_port = old_port
    old_ssh = current_ssh_port(dev.id)
    new_ssh = int(changes['ssh_port']) if 'ssh_port' in changes else old_ssh
    return {"ssl": (old_ssl, new_ssl), "api_port": (old_port, new_port), "ssh_port": (old_ssh, new_ssh),
            "user_name": changes.get("user_name"), "password": changes.get("password")}


def _service_rows(router):
    return {r.get('name'): r for r in tuple(router.api.path("/ip/service"))}


def _set_service(router, row, port, enable=True):
    params = {".id": row[".id"], "port": int(port)}
    if enable:
        params["disabled"] = False
    tuple(router.api.path("/ip/service")("set", **params))


def apply_on_router(dev, plan):
    """Change the router's /ip service ports for `plan` over the current API connection, then
    reconnect with the new settings. A router that does not answer with the new settings gets
    its old services back. Returns (ok, message)."""
    (old_ssl, new_ssl), (old_port, new_port), (old_ssh, new_ssh) = plan["ssl"], plan["api_port"], plan["ssh_port"]
    api_service = "api-ssl" if new_ssl else "api"
    want_api = (new_ssl, new_port) != (old_ssl, old_port)
    want_ssh = new_ssh != old_ssh
    if not want_api and not want_ssh:
        return True, "no router change needed"
    router = None
    undo = []
    try:
        options = util.build_api_options(dev)
        options['timeout'] = ROUTER_TIMEOUT
        router = RouterOSCheckResource(options)
        rows = _service_rows(router)
        for name, port, wanted in ((api_service, new_port, want_api), ("ssh", new_ssh, want_ssh)):
            if not wanted:
                continue
            row = rows.get(name)
            if row is None:
                raise RuntimeError("service '{}' not found on the router".format(name))
            undo.append((row, int(row.get('port')), bool(row.get('disabled'))))
            _set_service(router, row, port)
    except Exception as e:
        _undo(router, dev, undo)
        util.close_router(router)
        return False, "router change failed: {}".format(e)

    # the router must answer with the new API settings before the record changes
    if want_api:
        check = None
        try:
            new_options = dict(util.build_api_options(dev), ssl=new_ssl, port=new_port, timeout=ROUTER_TIMEOUT)
            check = RouterOSCheckResource(new_options)
            tuple(check.api.path("/system/identity"))
        except Exception as e:
            _undo(router, dev, undo)
            util.close_router(router)
            hint = " (API-SSL needs a certificate on the router's api-ssl service)" if new_ssl else ""
            return False, "router did not answer on {} port {}{}: {} - router change reverted".format(
                api_service, new_port, hint, e)
        finally:
            util.close_router(check)
    util.close_router(router)
    return True, "router updated"


def _undo(router, dev, undo):
    """Put the services changed by apply_on_router back (old port, old disabled state)."""
    if not undo:
        return
    target = router
    try:
        for row, port, disabled in reversed(undo):
            if target is None:
                options = util.build_api_options(dev)
                options['timeout'] = ROUTER_TIMEOUT
                target = RouterOSCheckResource(options)
            tuple(target.api.path("/ip/service")("set", **{".id": row[".id"], "port": port, "disabled": disabled}))
    except Exception as e:
        log.error("device %s: router service change could not be reverted: %s", dev.id, e)
    finally:
        if target is not router:
            util.close_router(target)


def save_record(dev, plan):
    """Write the planned values to the devices row, its PAM credentials and connection rows
    (same writes as the single-device edit form)."""
    (_, new_ssl), (_, new_port), (old_ssh, new_ssh) = plan["ssl"], plan["api_port"], plan["ssh_port"]
    user_name = plan["user_name"]
    password = plan["password"]
    enc_user = util.crypt_data(user_name) if user_name is not None else dev.user_name
    enc_pass = util.crypt_data(password) if password else False       # False = keep the stored one
    if not db_device.update_device(dev.id, enc_user, enc_pass, dev.ip, dev.peer_ip, dev.name, new_ssl, new_port):
        raise RuntimeError("device record not saved")
    fresh = db_device.Devices.get_by_id(dev.id)
    if user_name is not None or password:
        sync_device_credentials(fresh)
    sync_api_connection(dev.id, new_port, new_ssl)
    if new_ssh != old_ssh:
        set_ssh_port(dev.id, new_ssh)
