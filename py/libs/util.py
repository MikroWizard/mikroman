#!/usr/bin/python
# -*- coding: utf-8 -*-

# util.py: functions that we need :)
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import pytz
import datetime
import time
import uuid
import socket
import config
from libs.db import db_sysconfig,db_backups,db_events
from libs.db.db import database
from cryptography.fernet import Fernet 
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource, _safe_socket_read
from libs.check_routeros.routeros_check.helper import  RouterOSVersion
from typing import  Dict
import re
import json 
import logging
from libs.red import RedisDB
from libs import traffic_math
from libs.ssh_helper import SSH_Helper
import os
import netifaces
import librouteros
import librouteros.connections
import librouteros.exceptions

# EOF-safe, buffered librouteros socket reads (defined once in routeros_check.resource).
# Re-applied here so the patch holds no matter which module imported librouteros first.
librouteros.connections.SocketTransport.read = _safe_socket_read

log = logging.getLogger("util")
try:
    from libs import utilpro
    from libs import neighbour_pro as neighbour
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

try:
    from libs.credential_service import CredentialService
    from libs.db.db_pam import get_device_connection
    from libs.template_service import TemplateService
    from libs.terminal_gateway import initiate_session
except ImportError:
    pass

import urllib.request, urllib.parse, urllib.error

def close_router(router):
    """Safely close a RouterOSCheckResource or librouteros Api instance."""
    if not router:
        return
    try:
        if hasattr(router, 'close'):
            router.close()
        elif hasattr(router, '_api') and router._api:
            router._api.close()
    except Exception:
        pass

# --------------------------------------------------------------------------
# date related common methods

def parse_routeros_uptime(val):
    """Parse RouterOS uptime string into total integer seconds (see libs.traffic_math)."""
    return traffic_math.parse_routeros_uptime(val)

tz_hki = pytz.timezone("UTC")
tz_utc = pytz.utc

def utc2local(utc_dt, tz=tz_hki):
    """Convert UTC into local time, given tz."""
    if type(tz) is str:
        tz = pytz.timezone(tz)

    if not utc_dt:
        return utc_dt

    d = utc_dt.replace(tzinfo=tz_utc)
    return d.astimezone(tz)

def check_port(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((ip,int(port)))
    sock.close()
    if result == 0:
        return True
    else:
        return False

def crypt_data(text):
    # Encryption: Encrypting password using Fernet symmetric encryption 
    cipher_suite = Fernet(config.CRYPT_KEY) 
    # Encrypting 
    encrypted_password = cipher_suite.encrypt(text.encode()).decode() 
    return encrypted_password

def decrypt_data(text):
    # Encryption: Decrypting password using Fernet symmetric encryption 
    cipher_suite = Fernet(config.CRYPT_KEY) 
    # Decrypting password 
    decrypted_password = cipher_suite.decrypt(text.encode()).decode()
    return decrypted_password

def get_default_user_pass():
    default_user = db_sysconfig.get_default_user().value
    default_pass = db_sysconfig.get_default_password().value
    try:
        default_user=decrypt_data(default_user)
        default_pass=decrypt_data(default_pass)
    except:
        default_user="admin"
        default_pass=""
    return default_user,default_pass

def get_device_port(dev):
    try:
        if dev.port:
            return int(dev.port)
        conn = get_device_connection(dev.id, 'api')
        if conn and conn.port:
            return int(conn.port)
        return 8729 if getattr(dev, 'ssl', False) else 8728
    except:
        return 8729 if getattr(dev, 'ssl', False) else 8728

def get_mikrotik_service(dev, service_name, timeout=5):
    """Read a service (ssh/winbox/telnet/www...) from /ip/service over the API.

    Returns {'port': int, 'disabled': bool} or None when the device API is
    unreachable or the service row is missing. Callers fall back to their
    stored/default port on None.
    """
    router = None
    try:
        if not check_port(dev.ip, get_device_port(dev)):
            return None
        options = build_api_options(dev)
        options['timeout'] = timeout
        router = RouterOSCheckResource(options)
        for res in tuple(router.api.path("/ip/service")):
            if res.get('name') == service_name:
                return {
                    'port': int(res.get('port')),
                    'disabled': bool(res.get('disabled')),
                }
        return None
    except Exception as e:
        log.warning(f"Failed to read /ip/service {service_name} on device {dev.id}: {e}")
        return None
    finally:
        close_router(router)

def get_mikrotik_use_radius(dev, timeout=3):
    """Read /user/aaa use-radius over the API (read-only).

    Returns True/False, or None when the device API is unreachable or the value
    cannot be read. Callers must treat None as "unknown" and carry on as before.
    """
    router = None
    try:
        if not check_port(dev.ip, get_device_port(dev)):
            return None
        options = build_api_options(dev)
        options['timeout'] = timeout
        router = RouterOSCheckResource(options)
        aaa = tuple(router.api.path("/user/aaa"))
        if not aaa or 'use-radius' not in aaa[0]:
            return None
        val = aaa[0]['use-radius']
        if isinstance(val, str):
            return val.strip().lower() in ('true', 'yes')
        return bool(val)
    except Exception as e:
        log.warning(f"Failed to read /user/aaa on device {dev.id}: {e}")
        return None
    finally:
        close_router(router)

def _detect_source_ip(target_ip):
    """Local source IP the server uses to reach target_ip (UDP route lookup).

    UDP connect resolves the route without sending any packets, so this is
    multi-NIC/VLAN safe and instant.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        src = s.getsockname()[0]
        s.close()
        if src and src != "0.0.0.0":
            return src
    except Exception:
        pass
    return None

def resolve_peer_ip(dev):
    """Resolve the server IP used for device→server callbacks (syslog/radius/
    firmware/agent).

    peer_ip is always the MikroWizard server's IP (device → server direction).
    Uses the stored peer_ip; if empty, auto-detects the server's source IP for
    reaching the device's IP, falling back to the configured default_ip.
    Accepts a Devices model or a dict.
    """
    if isinstance(dev, dict):
        peer = dev.get("peer_ip") or ""
        target = dev.get("ip") or ""
    else:
        peer = getattr(dev, "peer_ip", "") or ""
        target = getattr(dev, "ip", "") or ""
    if peer:
        return peer
    if target:
        detected = _detect_source_ip(target)
        if detected:
            return detected
    try:
        return db_sysconfig.get_sysconfig("default_ip") or ""
    except Exception:
        return ""

def build_api_options(dev):
    default_user,default_pass= get_default_user_pass()
    username=decrypt_data(dev.user_name ) or default_user
    password=decrypt_data(dev.password ) or default_pass
    port=get_device_port(dev)
    ssl = bool(getattr(dev, 'ssl', False))

    # Resolve credentials from the new PAM structure (Task 18).  Port/ssl come
    # from the device row (authoritative) with the connection row used only as
    # a fallback inside get_device_port — this keeps device-edit and scanner
    # updates from being shadowed by a stale device_connections row.
    try:
        cred = CredentialService.get_credential_for_connection(dev.id, 'api')
        if cred and cred.get('username'):
            username = cred['username']
            if 'password' in cred:
                password = cred['password']
    except Exception:
        pass

    options={
       'host':dev.ip,
       'hostname': None,
       'username':username,
       'password':password,
       'routeros_version':'auto',
       'port':port,
        'ssl':ssl,
       'ssl_cafile': None,
       'ssl_capath': None,
       'ssl_force_no_certificate': False,
       'ssl_verify': False,
       'ssl_verify_hostname': False,
    }

    return options

def check_device_firmware_update(dev, q):
    port = get_device_port(dev)
    if not check_port(dev.ip, port):
        q.put({"id": dev.id, "update_availble": False, "reason": "Connection problem"})
        return

    options = build_api_options(dev)
    try:
        is_availbe, current, arch, upgrade_availble = check_update(options)
    except Exception as e:
        q.put({"id": dev.id, "update_availble": False, "reason": f"Unknown Reason: {e}"})
        return

    if is_availbe:
        q.put({"id": dev.id, "update_availble": is_availbe, "current_firmware": current, "arch": arch, "upgrade_availble": upgrade_availble})
    else:
        if current:
            q.put({"id": dev.id, "update_availble": is_availbe, "current_firmware": current, "arch": arch, "upgrade_availble": upgrade_availble})
        else:
            q.put({"id": dev.id, "reason": "Wrong user or password"})

def get_interfaces_counters(router):
    result = {}
    raw_ifaces = []
    try:
        raw_ifaces = list(router.api('/interface/print', stats=True))
    except Exception as e:
        log.warning(f"/interface/print with stats=True failed, trying standard print: {e}")
        try:
            raw_ifaces = list(router.api('/interface/print'))
        except Exception as e2:
            log.error(f"/interface/print failed: {e2}")
            return result

    for iface in raw_ifaces:
        name = iface.get('name')
        if name:
            result[name] = iface
    return result

def calculate_interface_rates(dev_id, interfaces, read_at=None):
    """
    Compute accurate poll-interval average rates (bps and pps) from 64-bit cumulative
    counters (rx-byte, tx-byte, rx-packet, tx-packet) cached in Redis (iface_counters::<dev_id>).

    Returns the set of interface names whose rates were computed from counters this poll.
    Interfaces not in the set (cold start, counter reset, missing counters) need a
    monitor-traffic fallback.

    read_at: when the counters were read. The rate divides the counter delta by the time
    between two reads, so the stamp must not include the Redis round trip that follows.
    """
    if not dev_id or not interfaces:
        return set()
    read_at = time.time() if read_at is None else read_at
    try:
        reddb = RedisDB({"dev_id": dev_id})
        prev_counters = reddb.get_cached_counters(dev_id)
        new_counters, valid = traffic_math.compute_interface_rates(prev_counters, interfaces, read_at)
        if new_counters:
            reddb.set_cached_counters(dev_id, new_counters, ttl=1800)
        return valid
    except Exception as e:
        log.error(f"Error calculating interface rates for dev {dev_id}: {e}")
        return set()

def get_traffic(router, interfaces):
    """Instantaneous rates via /interface/monitor-traffic (fallback source only)."""
    traffic = {}
    clean_interfaces = [
        i for i in interfaces
        if i and i != 'aggregate'
        and ',' not in i
        and not i.startswith(traffic_math.DYNAMIC_NAME_PREFIXES)
        and '<' not in i and '>' not in i
    ]
    # Small chunks: large monitor-traffic batches time out on busy PPPoE/VPN routers.
    chunk_size = 15
    for i in range(0, len(clean_interfaces), chunk_size):
        chunk = clean_interfaces[i:i + chunk_size]
        chunk_str = ",".join(chunk)
        params = {'interface': chunk_str, 'once': b' '}
        try:
            results = tuple(router.api('/interface/monitor-traffic', **params))
            for row in results:
                name = row.get('name')
                if name:
                    traffic[name] = {
                        'rx-packets-per-second': row.get('rx-packets-per-second', 0),
                        'rx-bits-per-second': row.get('rx-bits-per-second', 0),
                        'fp-rx-packets-per-second': row.get('fp-rx-packets-per-second', 0),
                        'fp-rx-bits-per-second': row.get('fp-rx-bits-per-second', 0),
                        'rx-drops-per-second': row.get('rx-drops-per-second', 0),
                        'rx-errors-per-second': row.get('rx-errors-per-second', 0),
                        'tx-packets-per-second': row.get('tx-packets-per-second', 0),
                        'tx-bits-per-second': row.get('tx-bits-per-second', 0),
                        'fp-tx-packets-per-second': row.get('fp-tx-packets-per-second', 0),
                        'fp-tx-bits-per-second': row.get('fp-tx-bits-per-second', 0),
                        'tx-drops-per-second': row.get('tx-drops-per-second', 0),
                        'tx-queue-drops-per-second': row.get('tx-queue-drops-per-second', 0),
                        'tx-errors-per-second': row.get('tx-errors-per-second', 0),
                    }
        except Exception as e:
            log.error(f"get_traffic error for interfaces {chunk_str}: {e}")
    return traffic

def get_interface_list(interfaces):
    interfaces = list(interfaces.keys())
    return interfaces

RATE_KEYS = ('rx-bits-per-second', 'tx-bits-per-second', 'rx-packets-per-second', 'tx-packets-per-second')

def mergeDictionary(dict_1, dict_2, counter_valid=None):
    """Merge /interface/print data (dict_1) with monitor-traffic data (dict_2), keyed by
    the real interface name (never default-name: renamed ports would collide).

    Rate source per interface: counter-based rate when the interface is in counter_valid
    (even if that rate is 0 = idle), otherwise the monitor-traffic value, otherwise 0.
    """
    counter_valid = counter_valid or set()
    dict_3 = {}
    keys = list(dict_1.keys())
    keys.extend(x for x in list(dict_2.keys()) if x not in keys)
    for key in keys:
        if key in dict_1 and key in dict_2:
            merged = {**dict_2[key], **dict_1[key]}
            if key not in counter_valid:
                for rk in RATE_KEYS:
                    merged[rk] = dict_2[key].get(rk, 0) or 0
            dict_3[key] = merged
        elif key in dict_1:
            dict_3[key] = {**dict_1[key]}
        else:
            dict_3[key] = {**dict_2[key]}
    return dict_3

def get_network_data(router, dev_id=None):
    """Interface table with per-interface rates.

    Steady state: rates come from counter deltas only (one /interface/print call).
    /interface/monitor-traffic is only called for interfaces without a valid counter
    baseline (first poll after start/upgrade, counter reset, or no stats support).
    """
    interfaces = get_interfaces_counters(router)
    read_at = time.time()
    counter_valid = calculate_interface_rates(dev_id, interfaces, read_at) if dev_id else set()
    fallback = traffic_math.monitor_traffic_candidates(interfaces, counter_valid)
    traffic = get_traffic(router, fallback) if fallback else {}
    return mergeDictionary(interfaces, traffic, counter_valid)

def check_or_fix_event(events,eventtype,detail,comment=False):
    if comment:
        found_event_id=next((item for item in events if item["eventtype"] == eventtype and item["detail"] == detail and comment in item["comment"]), False)        
    else:
        found_event_id=next((item for item in events if item["eventtype"] == eventtype and item["detail"] == detail), False)        
    if found_event_id:
        db_events.fix_event(found_event_id['id'])
        return True
    else:
        return False

def record_offline_zeros(dev):
    """Write 0 to the device's traffic rate sensors for this poll (device unreachable or
    API failed) so charts show real downtime. Non-traffic sensors are left as gaps."""
    try:
        try:
            sensors = json.loads(dev.sensors) if dev.sensors else []
        except Exception:
            sensors = []
        zero_keys = traffic_math.offline_zero_sensors(sensors)
        reddb = RedisDB({"dev_id": dev.id, "keys": zero_keys})
        reddb.add_dev_data({k: 0.0 for k in zero_keys})
    except Exception as e:
        log.warning(f"Could not record zero data for offline dev {getattr(dev, 'id', '?')}: {e}")

def fetch_reboot_reason(router, default):
    """Newest system log line explaining a reboot (topics may be 'system,error,critical',
    'system,info', ...). Falls back to default."""
    try:
        entries = list(router.api.path('/log'))
    except Exception as e:
        log.warning(f"Could not fetch reboot log: {e}")
        return default
    return traffic_math.pick_reboot_reason(entries, default)

# ---------------------------------------------------------------------------
# Poller API-options cache
# Building API options costs ~4-5 SQL queries + 3 decryptions per device (default
# credentials, PAM credential resolution, port). The poller does it for every device every
# minute. Options are cached per process for CREDENTIAL_CACHE_SECONDS; a failed login with
# cached options rebuilds them immediately (password rotated by vault / edited by admin).
CREDENTIAL_CACHE_SECONDS = int(getattr(config, "CREDENTIAL_CACHE_SECONDS", 300) or 0)
_api_options_cache = {}


def _api_options_key(dev):
    return (dev.id, dev.ip, str(getattr(dev, 'port', '') or ''), bool(getattr(dev, 'ssl', False)),
            getattr(dev, 'user_name', None), getattr(dev, 'password', None))


def get_api_options_cached(dev, now=None):
    """Returns (options, from_cache). Opens and releases its own DB connection only on a miss."""
    now = time.time() if now is None else now
    key = _api_options_key(dev)
    hit = _api_options_cache.get(dev.id)
    if CREDENTIAL_CACHE_SECONDS > 0 and hit and hit[0] == key and (now - hit[1]) < CREDENTIAL_CACHE_SECONDS:
        return dict(hit[2]), True
    with database.connection_context():
        options = build_api_options(dev)
    if CREDENTIAL_CACHE_SECONDS > 0:
        _api_options_cache[dev.id] = (key, now, dict(options))
    return options, False


def invalidate_api_options(dev_id):
    _api_options_cache.pop(dev_id, None)


def connect_router_for_poll(dev):
    """RouterOS API connection for the poller. A failure with cached options (e.g. password
    just rotated) is retried once with freshly built options."""
    options, from_cache = get_api_options_cached(dev)
    router = RouterOSCheckResource(options)
    try:
        router.api  # RouterOSCheckResource connects lazily: force the login here
        return router
    except Exception:
        invalidate_api_options(dev.id)
        close_router(router)
        if not from_cache:
            raise
        options, _ = get_api_options_cached(dev)
        router = RouterOSCheckResource(options)
        router.api
        return router


# ---------------------------------------------------------------------------
# Static (rarely-changing) device info cache for the poller
# routerboard, identity and wireless mode change rarely but cost 3 API commands per device
# per minute; syslog/RADIUS enforcement costs 2-5 more. They are refreshed every
# STATIC_POLL_SECONDS (default 300, 0 = every poll) and immediately after a reboot, while a
# firmware update is pending/running, or after the device was unreachable.
STATIC_POLL_SECONDS = int(getattr(config, "STATIC_POLL_SECONDS", 300) or 0)
_static_cache = {}


class _SkipStatic(Exception):
    pass


def invalidate_static_info(dev_id):
    _static_cache.pop(dev_id, None)


def static_refresh_due(dev, now=None):
    now = time.time() if now is None else now
    if STATIC_POLL_SECONDS <= 0:
        return True
    if getattr(dev, 'status', None) in ('updating', 'rebooting') or getattr(dev, 'firmware_to_install', None):
        return True
    hit = _static_cache.get(dev.id)
    return not hit or (now - hit['at']) >= STATIC_POLL_SECONDS


def _read_static_info(router):
    info = {'routerboard': None, 'identity': {}, 'wifi_result': None, 'device_type': 'router'}
    try:
        rb = tuple(router.api.path("/system/routerboard"))
        info['routerboard'] = dict(rb[0]) if rb else None
    except Exception as e:
        if 'no such command' not in str(e):
            log.error(e)
    ident = tuple(router.api.path("/system/identity"))
    info['identity'] = dict(ident[0]) if ident else {}
    try:
        wifi_results = tuple(router.api.path("/interface/wireless"))
        wifi_result = dict(wifi_results[0])
        info['wifi_result'] = wifi_result
        mode = wifi_result.get('mode')
        if mode in ['ap-bridge', 'bridge', 'wds-slave']:
            info['device_type'] = mode
        elif mode in ['station', 'station-wds', 'station-pseudobridge', 'station-pseudobridge-clone', 'station-bridge']:
            info['device_type'] = 'station'
        elif mode in ['alignment-only', 'nstreme-dual-slave']:
            info['device_type'] = 'special'
    except Exception:
        pass
    return info


def get_static_info(dev, router, refresh=False, now=None):
    now = time.time() if now is None else now
    hit = _static_cache.get(dev.id)
    if hit and not refresh:
        return hit['info']
    info = _read_static_info(router)
    _static_cache[dev.id] = {'at': now, 'info': info}
    return info


# Sensors written to Redis for internal use (network map mem %) but not shown as
# device-page charts. Kept out of dev.sensors.
UNCHARTED_SENSORS = {"total-memory"}

def grab_device_data(dev, q, sysconfig_flags=None, events_map=None):
    max_attempts = 3
    attempts = 0
    # Release the DB connection right away: never hold it across router I/O.
    with database.connection_context():
        port=get_device_port(dev)
    success = False
    curr_sec = None          # uptime (seconds) of a successful poll, for device_state
    time_to_wait=0.1
    while attempts < max_attempts:
        if check_port(dev.ip,port):
            success = True
            break
        attempts += 1
        time.sleep(time_to_wait)
        time_to_wait += 0.1
    if success:
        # get all device events which src is "Data Puller" and status is 0
        if events_map is not None:
            events = events_map.get(dev.id, [])
        else:
            with database.connection_context():
                events = list(db_events.get_events_by_src_and_status("Data Puller", 0, dev.id).dicts())
        if events:
            with database.connection_context():
                check_or_fix_event(events, "connection", "Unreachable")
        router = None
        try:
            router=connect_router_for_poll(dev)
            options=router._cmd_options
            # /system/resource once per poll (uptime, cpu, memory, version, arch).
            call = router.api.path(
              "/system/resource"
            )
            results = tuple(call)
            result: Dict[str, str] = dict(results[0])
            try:
                _installed_version = _version_from_resource(result)
            except Exception:
                _installed_version = router._get_routeros_version()
            resource_row = dict(result)
            try:
                call = router.api.path(
                  "/system/health"
                )
                health = tuple(call)
            except Exception as e:
                log.warning("Failed to fetch /system/health for {}: {}".format(dev.ip, e))
                health = ()

            # Rarely-changing data (routerboard, identity, wireless mode): every
            # STATIC_POLL_SECONDS, or immediately when the device is updating/rebooting.
            static_refresh = static_refresh_due(dev)
            static = get_static_info(dev, router, refresh=static_refresh)
            if static.get('routerboard'):
                result.update(static['routerboard'])
            result.update(static.get('identity') or {})
            device_type = static.get('device_type', 'router')
            wifi_result = static.get('wifi_result')
        except Exception as e:
            log.error(e)
            log.warning(dev.ip)
            q.put({"id": dev.id,"detail":"API Connection","reason":e,"done":False})
            invalidate_static_info(dev.id)
            record_offline_zeros(dev)
            return True
        if events:
            with database.connection_context():
                check_or_fix_event(events, "connection", "API Connection")
        try:
            keys=["free-memory","total-memory","cpu-load","free-hdd-space"]
            if len(health):
                #since routeros v7 they changed health res from api
                excluded_keys=['cpu-overtemp-check','active-fan','fan-mode','heater-control','psu2-state','cpu-overtemp-startup-delay','fan-on-threshold','heater-threshold','use-fan','cpu-overtemp-threshold','fan-switch','psu1-state','state','state-after-reboot']
                
                health_vals={}
                # Normalize health data to a dictionary
                # v7 format: [{'name': 'voltage', 'value': '24.1', 'type': 'V'}, ...]
                # v6 format: [{'voltage': '24.1', 'temperature': '30'}]
                
                # Check for v7 format
                is_v7_format = False
                if isinstance(health[0], dict) and 'name' in health[0] and 'value' in health[0]:
                    is_v7_format = True
                
                items_to_process = []
                if is_v7_format:
                    for item in health:
                        if 'name' in item and 'value' in item:
                             items_to_process.append((item['name'], item['value']))
                else:
                    # v6 format or single dict
                    for item in health:
                        for k, v in item.items():
                            items_to_process.append((k, v))

                for name, value in items_to_process:
                    if 'state' in name:
                        with database.connection_context():
                            if value == 'fail':
                                 db_events.health_event(dev.id, 'Data Puller', name, 'Critical', 0, "{} is Failed".format(name))
                            else:
                                 check_or_fix_event(events, "health", name)
                        # Don't add state to health_vals (Redis)
                        continue
                    
                    if name in excluded_keys:
                        continue

                    # Validate and convert value for Redis
                    try:
                        # 1. Strip units (e.g. "12.1V", "50C", "1547mA")
                        # Remove trailing letters/percents
                        val_clean = re.sub(r'[a-zA-Z%]+$', '', str(value)).strip()
                        
                        # 2. Convert to float
                        val = float(val_clean)
                        
                        # 3. Round to 2 decimal places
                        val = round(val, 2)
                        
                        health_vals[name] = val
                    except (ValueError, TypeError):
                        # Skip if conversion fails (e.g. ranges "50-55", strings "ok", "manual")
                        continue

                result.update(health_vals)
                keys.extend(list(health_vals.keys()))
        except Exception as e:
            log.warning(dev.ip)
            log.error(e)
            log.error(health)
            q.put({"id": dev.id,"reason":"Could not health data from device","detail":"Get Health","done":False})
            return True
        if events:
            with database.connection_context():
                check_or_fix_event(events, "connection", "Get Health")
        try:
            # arch=result['architecture-name']
            try:
                is_availbe , current , arch , upgrade_availble = check_update(
                    options, router=router, sysconfig_flags=sysconfig_flags,
                    prefetched={'resource': resource_row, 'routerboard': static.get('routerboard')})
                if dev.update_availble != is_availbe:
                    dev.update_availble = is_availbe
                if dev.upgrade_availble != upgrade_availble:
                    dev.upgrade_availble = upgrade_availble
                cur_str = str(current) if current else ""
                if dev.current_firmware != cur_str:
                    dev.current_firmware = cur_str
            except:
                pass
            if sysconfig_flags:
                force_syslog = sysconfig_flags.get('force_syslog', False)
                force_radius = sysconfig_flags.get('force_radius', False)
                rad_secret = sysconfig_flags.get('rad_secret', '')
            else:
                with database.connection_context():
                    force_syslog = True if db_sysconfig.get_sysconfig('force_syslog') == "True" else False
                    force_radius = True if db_sysconfig.get_sysconfig('force_radius') == "True" else False
                    rad_secret = db_sysconfig.get_sysconfig('rad_secret') if force_radius else ""
            if force_radius and static_refresh:
                try:
                    peer_ip = resolve_peer_ip(dev)
                    secret = rad_secret
                    res = configure_radius(router, peer_ip, secret)
                    with database.connection_context():
                        check_or_fix_event(events, "config", "radius configuration")
                except:
                    with database.connection_context():
                        db_events.config_event(dev.id, 'Data Puller', 'radius configuration', 'Error', 0, "Force radius Failed")
                    pass
            try:
                if not static_refresh:
                    # Syslog/RADIUS enforcement runs with the static refresh cadence.
                    raise _SkipStatic()
                syslog_configured = check_syslog_config(dev, router, force_syslog)
                if dev.syslog_configured != syslog_configured:
                    dev.syslog_configured = syslog_configured
                with database.connection_context():
                    check_or_fix_event(events, "config", "syslog configuration")
            except _SkipStatic:
                pass
            except:
                with database.connection_context():
                    db_events.config_event(dev.id, 'Data Puller', 'syslog configuration', 'Error', 0, "Force SysLog Failed")
                pass
            inst_ver_str = str(_installed_version) if _installed_version else ""
            if inst_ver_str and dev.current_firmware != inst_ver_str:
                dev.current_firmware = inst_ver_str
            try:
                if dev.firmware_to_install and _installed_version:
                    if RouterOSVersion(_installed_version) >= RouterOSVersion(dev.firmware_to_install):
                        dev.firmware_to_install = None
                        if dev.status in ['updating', 'rebooting']:
                            dev.status = 'updated'
                        dev.failed_attempt = 0
                        with database.connection_context():
                            check_or_fix_event(events, "firmware", "Update Failed")
                            check_or_fix_event(events, "firmware", "Download Failed")
                            check_or_fix_event(events, "firmware", "Device storage")
                            check_or_fix_event(events, "firmware", "Firmware repositpry")
            except Exception as e:
                log.warning(f"Error checking firmware completion in grab_device_data: {e}")
            new_uptime = result.get('uptime', '')
            curr_sec = parse_routeros_uptime(new_uptime)
            prev_sec = parse_routeros_uptime(dev.uptime)

            # Monotonic Uptime Guard & Unexpected Reboot Detection Invariant:
            # 1. If curr_sec < prev_sec on a running system, an unexpected reboot occurred (power cut, CPU temp, crash).
            # 2. If dev.uptime is empty or steady-state cadence (>= 600s / 10 mins) reached, update uptime in DB.
            is_reboot = bool(dev.uptime and curr_sec < prev_sec)
            cadence_reached = bool(not dev.uptime or (curr_sec - prev_sec >= 600) or is_reboot)

            if is_reboot:
                invalidate_static_info(dev.id)  # re-read routerboard/identity/wireless next poll
                was_expected = dev.status in ('updating', 'rebooting', 'upgrading')
                old_uptime_str = dev.uptime
                dev.uptime = new_uptime

                # Fetch detailed reboot reason from RouterOS system logs
                reboot_reason = f"Device reboot detected (uptime reset from {old_uptime_str} to {new_uptime})"
                if not was_expected:
                    reboot_reason = fetch_reboot_reason(router, reboot_reason)

                    with database.connection_context():
                        db_events.state_event(dev.id, "Data Puller", "Router Rebooted", "info", 1, reboot_reason)
                    log.info(f"Reboot detected on dev {dev.id} ({dev.ip}): {reboot_reason}")
            elif cadence_reached:
                dev.uptime = new_uptime

            if dev.router_type != device_type:
                dev.router_type = device_type
            if dev.name != result.get('name'):
                dev.name = result.get('name')
            if device_type != 'router':
                new_wifi = json.dumps(wifi_result, sort_keys=True)
                if dev.wifi_config != new_wifi:
                    dev.wifi_config = new_wifi

            interfaces = get_network_data(router, dev_id=dev.id)
            interfaces_keys = list(interfaces.keys())

            data = {}
            for key in keys:
                if key in result:
                    data[key] = result[key]
                else:
                    data[key] = 0

            # Device wire totals (bridge/bond members counted, containers/tunnels not).
            data.update(traffic_math.compute_device_totals(interfaces))

            for intkeys in interfaces_keys:
                iface_info = interfaces[intkeys]
                # Dynamic client tunnels are not registered as permanent TimeSeries / dev.sensors
                if traffic_math.is_dynamic_interface(intkeys, iface_info):
                    continue
                keys.extend(["rx-" + intkeys, "tx-" + intkeys, "rxp-" + intkeys, "txp-" + intkeys])
                data["rx-" + intkeys] = iface_info.get('rx-bits-per-second', 0) or 0
                data["tx-" + intkeys] = iface_info.get('tx-bits-per-second', 0) or 0
                data["rxp-" + intkeys] = iface_info.get('rx-packets-per-second', 0) or 0
                data["txp-" + intkeys] = iface_info.get('tx-packets-per-second', 0) or 0

            keys.extend(["rx-total", "tx-total", "rxp-total", "txp-total"])
            wireless_keys,wireless_data=[],[]
            neighbours=[]
            if ISPRO:
                try:
                   neighbour.get_neighbors(router,result,interfaces,dev.id)
                #show traceback of error
                except Exception as e:
                    #show traceback
                    log.error(f"Error: {e}")
                try:
                    wireless_keys,wireless_data=utilpro.wireless_actions(router,dev,events)
                except Exception as e:
                    log.error(e)
            if len(wireless_keys)>0:
                keys.extend(wireless_keys)
            data.update(wireless_data)
            redopts={
            "dev_id":dev.id,
            "keys":keys
            }
            reddb=RedisDB(redopts)
            
            with database.connection_context():
                try:
                    current_sensors = set(json.loads(dev.sensors)) if dev.sensors else set()
                except Exception:
                    current_sensors = set()
                new_sensors = set(keys) - UNCHARTED_SENSORS
                
                # Only trigger if we've found a brand new sensor we've never seen before
                # (or a stale uncharted one still registered from an older build)
                if (new_sensors - current_sensors) or (current_sensors & UNCHARTED_SENSORS):
                    log.info("updating keys for device {}".format(dev.id))
                    # Accumulate sensors so we don't forget temporarily disconnected ones
                    updated_sensors = sorted(current_sensors.union(new_sensors) - UNCHARTED_SENSORS)
                    dev.sensors = json.dumps(updated_sensors)
                    reddb.dev_create_keys()
                if dev.is_dirty():
                    dev.save(only=dev.dirty_fields)
                if events:
                    check_or_fix_event(events, "connection", "DB Write")
            reddb.add_dev_data(data)
        except Exception as e:
            log.error(e)
            log.warning(dev.ip)
            q.put({"id": dev.id,"reason":"Unable to store data in DB","detail":"DB Write","done":False})
            return True
        finally:
            close_router(router)
    else:
        q.put({"id": dev.id, "reason":"device not reachable with port {}".format(port),"detail":"Unreachable", "done":False})
        invalidate_static_info(dev.id)
        record_offline_zeros(dev)
        return True
    q.put({"id": dev.id,"done":True,'data':data,"uptime_s":curr_sec})
    return True


def check_syslog_config(dev,router,apply=False):
    own_router = False
    try:
        if not router:
            options=build_api_options(dev)
            router=RouterOSCheckResource(options)
            own_router = True
        peer_ip=resolve_peer_ip(dev)
        devid=dev.id
        call = router.api.path(
            "/system/logging/action"
        )
        #create syslog action 
        results = tuple(call)
        mikro1=[item for item in results if "mikrowizard" in item.get('name')]
        regex=r'^mikrowizard{}$'.format(devid)
        mikro=[item for item in mikro1 if re.match(regex,item.get('name'))]
        if len(mikro) == 1:
            action_name = mikro[0].get('name')
            if mikro[0].get('remote-port') == 5014 and mikro[0].get('remote') == peer_ip:
                # Configuration is already correct
                pass
            else:
                if apply:
                    log.info(f"Updating Peer IP for Syslog action {action_name} to {peer_ip}")
                    params = {
                        '.id': mikro[0].get('.id'),
                        'remote': peer_ip,
                        'remote-port': 5014
                    }
                    call.update(**params)
                else:
                    return False
        else:
            if apply:
                if len(mikro1):
                    ids = [item.get('.id') for item in mikro1]
                    if len(ids):
                        log.info(f"Removing old Syslog actions: {ids}")
                        call.remove(*ids)
                
                action_name = f'mikrowizard{devid}'
                log.info(f"Creating new Syslog action {action_name} with Peer IP {peer_ip}")
                action = {
                    'name': action_name,
                    'remote': peer_ip,
                    'remote-port': 5014,
                    'target': 'remote'
                }
                call.add(**action)
            else:
                return False

        #create loggings 
        call = router.api.path(
            "/system/logging"
        )

        results = tuple(call)

        confs=[item for item in results if action_name == item.get('action') and action_name == item.get('prefix')]
        if len(confs)!=3:
            if apply:
                ids=[item.get('.id') for item in results if 'mikrowizard' in item.get('prefix')]
                if len(ids):
                    call.remove(*ids)
                keys=['critical','error','info']
                for key in keys:
                    action={
                    'action':action_name, 
                    'topics':key,
                    'prefix':action_name,
                    }
                    res=call.add(**action )
            else:
                return False
        return True
    except Exception as e:
        log.error(e)
        return False
    finally:
        if own_router and router:
            close_router(router)

def apply_perm(router,name,perms):
    try:
      #check if radius client is configured and ip ,port,secret is correct
        call = router.api.path(
            "/user/group"
        )
        groups = tuple(call)
        exist=False
        for group in groups:
            if group.get('name')==name:
                exist=group.get('.id')
                p1=group.get('policy').split(',')
                p1.sort()
                if p1==perms:
                    return True
        params={
            'name':name,
            'policy':(',').join(perms)
        }
        try:
            if not exist:
                res=call.add(**params)
            else:
                params['.id']=exist
                call.update(**params)
                return True
            if res:
                return True
        except Exception as e:
            log.error(e)
            return False
    except Exception as e:
       log.error(e)
       return False

def configure_radius(router,ip,secret):
    try:
        #check if radius client is configured and ip ,port,secret is correct
        call = router.api.path(
            "/radius"
        )
        call2 = router.api.path(
            "/user/aaa"
        )
        radius = tuple(call)
        aaa = tuple(call2)
        if not aaa[0]['use-radius'] or not aaa[0]['accounting'] or not aaa[0]['interim-update']=='0s':
            params={
            'use-radius':True,
            'accounting':True,
            'interim-update':'0s'
            }
            tuple(router.api.path('user', 'aaa')('set', **params))
        target_comment = 'mikrowizard'
        
        radius_list = list(radius)
        target_comment = 'mikrowizard'
        
        # 1. Identify candidates
        perfect_match = None
        ip_secret_match = None
        comment_match = None
        ip_match = None
        
        for res in radius_list:
            rid = res.get('.id')
            r_ip = res.get('address')
            r_secret = res.get('secret')
            r_comment = res.get('comment')
            
            if r_comment == target_comment:
                if r_ip == ip and r_secret == secret:
                    perfect_match = rid
                elif not comment_match:
                    comment_match = rid
            elif r_ip == ip:
                if r_secret == secret:
                    if not ip_secret_match:
                        ip_secret_match = rid
                else:
                    if not ip_match:
                        ip_match = rid
        
        # 2. Pick the winner
        primary_id = perfect_match or ip_secret_match or comment_match or ip_match
        
        # 3. Identify losers
        to_remove = []
        for res in radius_list:
            rid = res.get('.id')
            if rid == primary_id:
                continue
            
            # Remove duplicates for target IP or redundant managed entries
            if res.get('address') == ip or res.get('comment') == target_comment:
                to_remove.append(rid)

        # Execute removal
        if to_remove:
            log.warning(f"Removing {len(to_remove)} redundant RADIUS entries for {ip}: {to_remove}")
            try:
                call.remove(*to_remove)
            except Exception as e:
                log.error(f"Failed to remove RADIUS entries: {e}")
        else:
            if os.getenv("DEV_MODE") == "true":
                log.info(f"No redundant RADIUS entries found for {ip}")

        # Now manage the primary entry
        if primary_id:
            # Re-fetch the entry data from our local tuple to see what needs updating
            p_entry = next((r for r in radius if r.get('.id') == primary_id), None)
            if p_entry:
                if p_entry.get('address') == ip and p_entry.get('secret') == secret and p_entry.get('comment') == target_comment:
                    # Already perfect
                    return True
                else:
                    log.info(f"Synchronizing RADIUS entry {primary_id} to {ip} (comment: {target_comment})")
                    params = {
                        '.id': primary_id,
                        'address': ip,
                        'secret': secret,
                        'comment': target_comment,
                        'service': 'login'
                    }
                    try:
                        call.update(**params)
                        return True
                    except Exception as e:
                        log.error(f"Failed to update RADIUS entry: {e}")
                        return False


        # configure radius client
        action = {
            'address': ip, 
            'secret': secret,
            'service': 'login',
            'require-message-auth': 'no',
            'comment': target_comment
        }
        try:
            call.add(**action)
        except:
            if 'require-message-auth' in action:
                action.pop('require-message-auth')
            call.add(**action)
        
        return True 
    except Exception as e:
        log.error(e)
        return False

def FourcePermToRouter(dev,perm):
    router = None
    try:
        options=build_api_options(dev)
        router=RouterOSCheckResource(options)
        peer_ip=resolve_peer_ip(dev)
        secret = db_sysconfig.get_sysconfig('rad_secret')
        res = configure_radius(router, peer_ip,secret)
        try:
            pl=json.loads(perm[0].perm_id.perms)
            perms=[p if pl[p] else '!{}'.format(p) for p in pl]
            perms.sort()
            _installed_version=router._get_routeros_version()
            if _installed_version > RouterOSVersion('7.6'):
                if "!dude" in perms:
                    perms.remove("!dude")
                elif "dude" in perms:
                    perms.remove("dude")
            if _installed_version > RouterOSVersion('7.2'):
                if "!tikapp" in perms:
                    perms.remove("!tikapp")
                elif "tikapp" in perms:
                    perms.remove("tikapp")
            if _installed_version < RouterOSVersion('7.1'):
                if "!rest-api" in perms:
                    perms.remove("!rest-api")
                elif "rest-api" in perms:
                    perms.remove("rest-api")
            res2=apply_perm(router,perm[0].perm_id.name,perms)
            return res2
        except Exception as e:
            log.error(e)
            pass
        return False
    except Exception as e:
        log.error(e)
        return False
    finally:
        close_router(router)

def _version_from_resource(resource):
    """RouterOSVersion from a /system/resource row ('7.17 (stable)' -> 7.17)."""
    return RouterOSVersion(str(resource.get("version", "")).partition(" ")[0])


def check_update(options, router=False, sysconfig_flags=None, prefetched=None):
    """(update_available, installed_version, arch, routerboard_upgrade).

    prefetched: optional {'resource': dict, 'routerboard': dict|None} already read by the
    caller in this poll - avoids re-reading /system/resource and /system/routerboard.
    'routerboard': None means "no RouterBOARD" (CHR/x86) and is not re-queried.
    """
    # Safe lookup of sysconfig with cached flags or graceful fallbacks
    if sysconfig_flags:
        ofa = sysconfig_flags.get('old_firmware_action', 'keep')
        cached_old_ver = sysconfig_flags.get('old_version')
        cached_latest_ver = sysconfig_flags.get('latest_version')
    else:
        try:
            with database.connection_context():
                ofa_cfg = db_sysconfig.get_sysconfig('old_firmware_action')
                ofa = ofa_cfg if ofa_cfg else "keep"
        except Exception:
            ofa = "keep"
        cached_old_ver = None
        cached_latest_ver = None

    own_router = False
    try:
        if prefetched and prefetched.get('resource'):
            _installed_version = _version_from_resource(prefetched['resource'])
        else:
            if not router:
                router = RouterOSCheckResource(options)
                own_router = True
            _installed_version = router._get_routeros_version()
        try:
            if ofa == "keep" and _installed_version < RouterOSVersion('6.99.99'):
                if cached_old_ver is not None:
                    old_ver = cached_old_ver
                else:
                    with database.connection_context():
                        old_ver = db_sysconfig.get_sysconfig('old_version')
                _latest_version = RouterOSVersion(str(old_ver)) if old_ver else False
            else:
                if cached_latest_ver is not None:
                    latest_ver = cached_latest_ver
                else:
                    with database.connection_context():
                        latest_ver = db_sysconfig.get_sysconfig('latest_version')
                _latest_version = RouterOSVersion(str(latest_ver)) if latest_ver else False
        except Exception:
            _latest_version = False

        if prefetched and prefetched.get('resource'):
            result = dict(prefetched['resource'])
        else:
            call = router.api.path("/system/resource")
            results = tuple(call)
            result: Dict[str, str] = results[0] if results else {}
        arch = result.get('architecture-name', '')

        # RouterBOARD inspection (safe against virtual, CHR, and empty responses)
        upgrade = False
        try:
            if prefetched and 'routerboard' in prefetched:
                rb_results = (prefetched['routerboard'],) if prefetched['routerboard'] else ()
            else:
                call_rb = router.api.path("/system/routerboard")
                rb_results = tuple(call_rb)
            if rb_results:
                result.update(rb_results[0])
                current_rb = result.get('current-firmware')
                upgrade_rb = result.get('upgrade-firmware')
                board_name = result.get('board-name', '')
                if current_rb and upgrade_rb and 'x86' not in arch and 'x86' not in board_name:
                    if current_rb != upgrade_rb:
                        upgrade = True
        except Exception as e:
            if 'no such command' not in str(e):
                log.warning(f"Could not check routerboard for {options.get('host')}: {e}")

        if _latest_version and _installed_version < _latest_version:
            return True, _installed_version, arch, upgrade
        else:
            return False, _installed_version, arch, upgrade
    except Exception as e:
        log.error("Error during firmware check for host : {}".format(options.get("host", "?")))
        log.error(e)
        return False, False, False, False
    finally:
        if own_router and router:
            close_router(router)

def log_alert(type, dev, massage):
    if isinstance(dev, int):
        dev_ip = "Device {}".format(dev)
    else:
        dev_ip = getattr(dev, "ip", str(dev))
    log.error("Alert: {} {} Device: {} ".format(type, massage, dev_ip))

def backup_routers(dev,q):
    status=backup_router(dev)
    q.put({"id": dev.id,"devip":dev.ip,"state":status})

def run_snippets(dev, snippet,q, template_key=None):
    result=run_snippet(dev, snippet, template_key=template_key)
    q.put({"devid": dev.id,"devip": dev.ip,"devname": dev.name, "status":True if result else False , "result":result if result else 'Exec Failed'})
    return result

def run_snippet(dev, snippet, template_key=None):
    # Task 19: Check if this is a Mikrotik device or uses the legacy RouterOS API path
    is_mikrotik = not dev.device_type or dev.device_type == 'mikrotik'
    
    # If a template_key is provided AND it's not a Mikrotik device, route through PAM Terminal Gateway
    if not is_mikrotik and template_key:
        try:
            t_dict = TemplateService.get_template_for_device(dev.id)
            if not t_dict:
                return f"No template found for device_type {dev.device_type}"
                
            command = TemplateService.resolve_command(t_dict, template_key)
            if not command:
                return f"Template command key '{template_key}' not found in template."
                
            # Execute standard string replacements like the legacy path
            if '[mikrowizard]' in command:
                command = command.replace('[mikrowizard]', resolve_peer_ip(dev))
                
            # If the snippet is meant to be a script parameter rather than a standalone command, we format it here
            if snippet and '{snippet}' in command:
                command = command.replace('{snippet}', snippet)
            elif snippet:
                command = f"{command} {snippet}"
                
            # 2. Find connection details
            conn = get_device_connection(dev.id, 'ssh') or get_device_connection(dev.id, 'telnet')
            if not conn:
                return "No SSH/Telnet connection defined for this device."
                
            # 3. Request execution from the gateway
            session_id = str(uuid.uuid4())
            callback_url = f"{config.MY_URL}/api/pam/webhook" if hasattr(config, 'MY_URL') else f"http://127.0.0.1:8000/api/pam/webhook"
            
            init_res = initiate_session(
                dev.ip, conn.port, None, None, conn.protocol, session_id, callback_url,
                template=t_dict, credential_id=conn.credential_id, device_id=dev.id,
                connection_id=conn.id, run_command=command
            )
            
            if not init_res.get('success'):
                return f"Gateway execution failed: {init_res.get('error', 'Unknown Error')}"
                
            # The execution is async. Wait briefly or return the session tracking ID
            return f"Execution spawned via PAM Terminal Gateway. Session ID: {session_id}"
            
        except Exception as e:
            log.error(f"PAM snippet execution error: {e}")
            return f"PAM Error: {e}"

    # --- LEGACY MIKROTIK ROUTEROS API PATH ---
    port=get_device_port(dev)
    router = None
    try:
        if check_port(dev.ip,port):
            options=build_api_options(dev)
            options['timeout']=120
            #check ssh service status
            router=RouterOSCheckResource(options)
            options['router']=router
            call = router.api.path(
                "/ip/service"
            )
            results = tuple(call)
            ssh_info={}
            for res in results:
                if res['name'] == 'ssh':
                    ssh_info['disabled']=res['disabled']
                    ssh_info['.id']=res['.id']
                    options['ssh_port']=res['port']
                    break
            #enable ssh if disabled
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': False, '.id' : ssh_info['.id']}
                call.update(**params)
            try:
                ssh=SSH_Helper(options)
                result=ssh.exec_command(snippet)
                if not result:
                    result="executed successfully"
                if "no such item" in result:
                    result=False
            except Exception as e:
                log.error(e)
                log_alert('ssh',dev,'During backup ssh error')
            if ssh_info['disabled']:
                #undo ssh config after finishing backup
                params = {'disabled': True, '.id' : ssh_info['.id']}
                call.update(**params)
            return result
        else:
            log_alert('connection',dev,'During backup error with connectiong to api')
            return False
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when connecting to ssh')
        return False
    finally:
        close_router(router)

def backup_router(dev):
    port=get_device_port(dev)
    router = None
    try:
        if check_port(dev.ip,port):
            options=build_api_options(dev)
            options['timeout']=120
            #check ssh service status
            router=RouterOSCheckResource(options)
            options['router']=router
            call = router.api.path(
                "/ip/service"
            )
            results = tuple(call)
            ssh_info={}
            for res in results:
                if res['name'] == 'ssh':
                    ssh_info['disabled']=res['disabled']
                    ssh_info['.id']=res['.id']
                    options['ssh_port']=res['port']
                    break
            #enable ssh if disabled
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': False, '.id' : ssh_info['.id']}
                call.update(**params)
            try:
                ssh=SSH_Helper(options)
                configs=ssh.get_config()
                state=store_config(dev,configs)
                
            except Exception as e:
                log.error(e)
                log_alert('ssh',dev,'During backup ssh error')
            if ssh_info['disabled']:
                #ssh is disabled we need to enable it
                params = {'disabled': True, '.id' : ssh_info['.id']}
                call.update(**params)
            return True
        else:
            log_alert('connection',dev,'During backup error with connectiong to api')
            return False
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when connecting to ssh')
        return False
    finally:
        close_router(router)

def store_config(dev,configs):
    dir=config.BACKUP_DIR
    #add device mac and curent date to dir
    identifier=dev.mac
    if identifier=='tunnel':
        identifier=identifier+"_devid_"+(str(dev.id))
    dir=dir+identifier+"/"+datetime.datetime.now().strftime("%Y-%m-%d")+"/"
    filename=datetime.datetime.now().strftime("%H-%M-%S")+".txt"
    filedir=dir+filename
    try:
        if not os.path.exists(dir):
            os.makedirs(dir)
        #store config file
        with open(filedir, "w") as text_file:
            text_file.write(configs)
        #add record to db
        db_backups.create(
            dev=dev,
            directory=filedir,
            size=os.path.getsize(filedir),
            )
        return True
    except Exception as e:
        log.error(e)
        log_alert('backup',dev,'Problem During backup when saving file')
        return False


def get_ethernet_wifi_interfaces():
    interfaces = netifaces.interfaces()
    ethernet_wifi_interfaces = []
    interfaces.sort()
    for interface in interfaces:
        try:
            addr = netifaces.ifaddresses(interface)
            if 17 in addr.keys():
                if re.match(r'(en|wl|eth).*',interface):
                    ethernet_wifi_interfaces.append({'interface':interface
                                                     ,'mac':addr[17][0]['addr']})
        except Exception as e:
            log.error(e)
            pass
    return ethernet_wifi_interfaces

def generate_serial_number(interfaces):
    mac_addresses = []
    for interface in interfaces:
        try:
            mac_addresses.append(interface['mac'])
        except Exception as e:
            pass
    if len(mac_addresses)>0:
        # Sort the MAC addresses to ensure consistent ordering
        mac_addresses.sort()
        # Concatenate the MAC addresses into a single string
        mac_string = ''.join(mac_addresses)
        # Generate a UUID based on the MAC string
        hwid = "mw" +  str(uuid.uuid5(uuid.NAMESPACE_DNS, mac_string))
        return str(hwid)
    else:
        return None

def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def get_local_users(opts,router=False,full=False):
    own_router = False
    try:
        if not router:
            router=RouterOSCheckResource(opts)
            own_router = True
        call = router.api.path(
            "/user"
        )
        if not full:
            results=[a['name'] for a in  tuple(call)]
        else:
            results=tuple(call)
        return results
    except Exception as e:
        log.error(e)
        return False
    finally:
        if own_router and router:
            close_router(router)

def delete_file(file):
    try:
        #check if file exist:
        if not os.path.exists(file):
            return True
        os.remove(file)
        return True
    except Exception as e:
        log.error(e)
        return False
def ispro():
    return ISPRO

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)


