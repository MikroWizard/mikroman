#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process as a syslog server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import asyncio
import time
import logging
import re
from threading import Lock

from libs.db import db_device, db_AA, db_events
from libs import util
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

log = logging.getLogger("SYSLOG")

# Cache for devices and users to reduce DB calls
device_cache = {}
user_cache = {}
message_cache = {}  # Deduplication cache
cache_lock = Lock()
CACHE_TTL = 300  # 5 minutes for devices
USER_CACHE_TTL = 30  # 30 seconds for users (frequent changes)
MESSAGE_DEDUP_TTL = 5  # 5 seconds for message deduplication
last_cleanup = 0
CLEANUP_INTERVAL = 600  # 10 minutes

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    @staticmethod
    def get_cached_device(ip):
        """Get device from cache or database"""
        with cache_lock:
            now = time.time()
            if ip in device_cache:
                dev, timestamp = device_cache[ip]
                if now - timestamp < CACHE_TTL:
                    return dev
            
            # Cache miss or expired
            dev = db_device.query_device_by_ip(ip)
            if dev:
                device_cache[ip] = (dev, now)
            return dev
    
    @staticmethod
    def get_cached_users(dev_id, opts):
        """Get users from cache or API"""
        with cache_lock:
            now = time.time()
            if dev_id in user_cache:
                users, timestamp = user_cache[dev_id]
                if now - timestamp < USER_CACHE_TTL:
                    return users
            
            # Cache miss or expired
            users = util.get_local_users(opts)
            if users:
                user_cache[dev_id] = (users, now)
            return users or []
    
    @staticmethod
    def is_duplicate_message(addr, message):
        """Check if message is duplicate within dedup window"""
        with cache_lock:
            now = time.time()
            key = f"{addr[0]}:{hash(message)}"
            
            if key in message_cache:
                last_seen = message_cache[key]
                if now - last_seen < MESSAGE_DEDUP_TTL:
                    return True
            
            message_cache[key] = now
            return False
    
    @staticmethod
    def cleanup_cache_if_needed():
        """Non-blocking cache cleanup with minimal lock time"""
        global last_cleanup
        now = time.time()
        
        # Only attempt cleanup every 10 minutes and if we can get lock immediately
        if now - last_cleanup > CLEANUP_INTERVAL and cache_lock.acquire(blocking=False):
            try:
                last_cleanup = now
                # Quick cleanup - build new dicts instead of iterating and deleting
                device_cutoff = now - CACHE_TTL
                user_cutoff = now - USER_CACHE_TTL
                message_cutoff = now - MESSAGE_DEDUP_TTL
                new_device_cache = {ip: (dev, ts) for ip, (dev, ts) in device_cache.items() if ts > device_cutoff}
                new_user_cache = {dev_id: (users, ts) for dev_id, (users, ts) in user_cache.items() if ts > user_cutoff}
                new_message_cache = {key: ts for key, ts in message_cache.items() if ts > message_cutoff}
                device_cache.clear()
                device_cache.update(new_device_cache)
                user_cache.clear()
                user_cache.update(new_user_cache)
                message_cache.clear()
                message_cache.update(new_message_cache)
            finally:
                cache_lock.release()
    # Pre-compiled regex patterns for better performance
    DEVICE_ID_REGEX = re.compile(r'(.*),?(info.*|warning|critical|error) mikrowizard(\d+):.*')
    LOGIN_REGEX = re.compile(r"user (.*) logged (in|out) from (..*)via.(.*)")
    LOGIN_FAILURE_REGEX = re.compile(r"login failure for user (.*) from (..*)via.(.*)")
    REBOOT_REGEX = re.compile(r'system,error,critical mikrowizard\d+: (.*)')
    SYSTEM_INFO_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (winbox-\d.{1,3}\d\/.*\(winbox\)|mac-msg\(winbox\)|tcp-msg\(winbox\)|ssh|telnet|api|api-ssl|console|.*\/web|ftp|www-ssl).*:(.*)@(.*) \((.*)\)")
    BUGGED_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by  \((.*)\)")
    FALLBACK_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (.*)")
    LINK_REGEX = re.compile(r"interface,info mikrowizard\d+: (.*) link (down|up).*")
    DHCP_REGEX = re.compile(r'dhcp,(?:info|warning|critical|error)(?:,info|,warning|,critical|,error)? mikrowizard\d+: (.*)')
    WIRELESS_REGEX = re.compile(r'wireless,info mikrowizard\d+: ([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})@(.*): (connected|disconnected), (signal strength|.*)? (-?\d{2})?.*')
    def extract_data_from_regex(self, regex, line):
        try:
            matches = re.finditer(regex, line, re.MULTILINE)
            sgroups = []
            for matchNum, match in enumerate(matches, start=1):
                for groupNum in range(0, len(match.groups())):
                    groupNum = groupNum + 1
                    sgroups.append(match.group(groupNum))
            return sgroups
        except Exception as e:
            log.error(f"Regex error: {e}")
            return None

    def safe_extract_info(self, compiled_regex, message, min_groups=0):
        """Safely extract regex groups with bounds checking"""
        try:
            info = self.extract_data_from_regex(compiled_regex.pattern, message)
            if info is None or len(info) < min_groups:
                return None
            return info
        except Exception as e:
            log.error(f"Error extracting regex data: {e}")
            return None

    def datagram_received(self, data, addr):
        """Called when a datagram is received"""
        asyncio.create_task(self.handle_log(data, addr))

    async def handle_log(self, data, addr):
        try:
            message = data.strip().decode('utf-8', errors='ignore')
            
            # Check for duplicate messages
            if self.is_duplicate_message(addr, message):
                return
                
            log.warning(f"Received syslog message from {addr[0]}: {message}")
            ts = int(time.time())
            
            # Periodic non-blocking cache cleanup
            self.cleanup_cache_if_needed()
            
            # Use cached device lookup
            dev = self.get_cached_device(addr[0])
            if not dev:
                return
                
            info = self.safe_extract_info(self.DEVICE_ID_REGEX, message, 3)
            if not info:
                return
                
            try:
                device_id = int(info[2])
                if dev.id != device_id:
                    log.error(f"Device id mismatch ignoring syslog for ip: {addr[0]}")
                    return
            except (ValueError, IndexError) as e:
                log.error(f"Invalid device ID in message: {e}")
                return
                
            # Use cached user lookup only when needed
            opts = util.build_api_options(dev)
            users = None  # Lazy load users only when needed
        except Exception as e:
            log.error(f"Error in handle_log: {e}")
            return
        if 'mikrowizard' in message and 'via api' not in message:
            if 'system,info,account' in message:
                login_info = self.safe_extract_info(self.LOGIN_REGEX, message, 4)
                if login_info:
                    try:
                        if users is None:
                            users = self.get_cached_users(dev.id, opts)
                        msg = 'local' if login_info[0] in users else 'radius'
                        if 'logged in' in message and 'via api' not in message:
                            db_AA.Auth.add_log(dev.id, 'loggedin', login_info[0], login_info[2], login_info[3], timestamp=ts, message=msg)
                        elif 'logged out' in message and login_info[0] in users:
                            db_AA.Auth.add_log(dev.id, 'loggedout', login_info[0], login_info[2], login_info[3], timestamp=ts, message=msg)
                    except Exception as e:
                        log.error(f"Error processing login: {e}")
                        log.error(message)
            elif 'system,error,critical' in message:
                if "login failure" in message:
                    failure_info = self.safe_extract_info(self.LOGIN_FAILURE_REGEX, message, 3)
                    if failure_info:
                        if users is None:
                            users = self.get_cached_users(dev.id, opts)
                        msg = 'local' if failure_info[0] in users else 'radius'
                        db_AA.Auth.add_log(dev.id, 'failed', failure_info[0], failure_info[1], failure_info[2], timestamp=ts, message=msg)
                elif "rebooted" in message:
                    reboot_info = self.safe_extract_info(self.REBOOT_REGEX, message, 1)
                    if reboot_info:
                        db_events.state_event(dev.id, "syslog", "Unexpected Reboot", "Critical", 1, reboot_info[0])
                    
            elif 'system,info mikrowizard' in message:
                if ISPRO:
                    utilpro.do_pro("syslog", False, dev, message)
                    
                system_info = self.safe_extract_info(self.SYSTEM_INFO_REGEX, message, 6)
                if system_info:
                    address = system_info[4].split('/')
                    ctype = self._determine_connection_type(system_info[2], address)
                    db_AA.Account.add_log(dev.id, system_info[0], system_info[1], system_info[3], message, ctype, address[0], system_info[5])
                else:
                    bugged_info = self.safe_extract_info(self.BUGGED_REGEX, message, 3)
                    if bugged_info:
                        db_AA.Account.add_log(dev.id, bugged_info[0], bugged_info[1], "Unknown (Mikrotik Bug)", message, config=bugged_info[2])
                    elif "rebooted" in message:
                        db_events.state_event(dev.id, "syslog", "Router Rebooted", "info", 1, info[0])
                    elif "resetting system configuration" in message:
                        db_events.state_event(dev.id, "syslog", "Router reset", "info", 1, info[0])
                    else:
                        fallback_info = self.safe_extract_info(self.FALLBACK_REGEX, message, 3)
                        if fallback_info:
                            db_AA.Account.add_log(dev.id, fallback_info[0], fallback_info[1], fallback_info[2], message)
            elif 'interface,info mikrowizard' in message:
                events = list(db_events.get_events_by_src_and_status("syslog", 0, dev.id).dicts())
                if "link down" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        db_events.state_event(dev.id, "syslog", f"Link Down: {link_info[0]}", "Warning", 0, f"Link is down for {link_info[0]}")
                elif "link up" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        util.check_or_fix_event(events, 'state', f"Link Down: {link_info[0]}")
            elif any(term in message for term in ["dhcp,info", "dhcp,critical", "dhcp,warning", "dhcp,error"]):
                client_type = 'client' if " dhcp-client on" in message else 'server'
                
                dhcp_info = self.safe_extract_info(self.DHCP_REGEX, message, 1)
                if not dhcp_info:
                    return
                    
                level = "info"
                if "dhcp,warning" in message:
                    level = "warning"
                elif "dhcp,critical" in message:
                    level = "critical"
                elif "dhcp,error" in message:
                    level = "error"
                    
                if client_type == 'server':
                    if "deassigned" in message:
                        db_events.state_event(dev.id, "syslog", "dhcp deassigned", level, 1, dhcp_info[0])
                    elif "assigned" in message:
                        db_events.state_event(dev.id, "syslog", "dhcp assigned", level, 1, dhcp_info[0])
                else:
                    db_events.state_event(dev.id, "syslog", "dhcp client", level, 1, dhcp_info[0])
            elif "wireless,info mikrowizard" in message:
                if ISPRO:
                    utilpro.wireless_syslog_event(dev, message)
                else:
                    wireless_info = self.safe_extract_info(self.WIRELESS_REGEX, message, 3)
                    if wireless_info:
                        strength = wireless_info[4] if len(wireless_info) > 4 else ""
                        db_events.state_event(dev.id, "syslog", "wireless client", "info", 1, 
                                            f"{wireless_info[0]} {wireless_info[1]} {wireless_info[2]} {wireless_info[3]} {strength}")
            else:
                log.error(message)

    def _determine_connection_type(self, connection_info, address):
        """Determine connection type from syslog info"""
        ctype = ''
        if 'winbox' in connection_info:
            ctype = 'winbox'
            if 'tcp' in connection_info:
                ctype = 'winbox-tcp'
            elif 'mac' in connection_info:
                ctype = 'winbox-mac'
            if 'terminal' in address:
                ctype += '/terminal'
        elif 'ssh' in connection_info:
            ctype = 'ssh'
        elif 'telnet' in connection_info:
            ctype = 'telnet'
        elif '/web' in connection_info:
            parts = connection_info.split('/')
            ctype = f"{parts[1]} ({parts[0]})"
        elif 'api' in connection_info:
            ctype = 'api'
        elif 'console' in connection_info:
            ctype = 'console'
        return ctype

async def main():
    """Main async function to start the UDP server"""
    loop = asyncio.get_running_loop()
    
    # Create UDP server
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(),
        local_addr=('0.0.0.0', 5014)
    )
    
    log.info("Async syslog server started on port 5014")
    
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        log.info("Shutting down server")
    finally:
        transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server stopped")
