#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process as a syslog server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import asyncio
import time
import logging
import re
import os

from libs.db import db_device, db_AA, db_events, db_sysconfig
from libs import util
try:
    from libs import utilpro, syslog_regex_pro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

log = logging.getLogger("SYSLOG")

# Cache for devices and users to reduce DB calls
# NOTE: asyncio event loop is single-threaded — these dicts are safe
# to read/write from coroutines without any locking.
device_cache = {}
user_cache = {}
message_cache = {}  # Deduplication cache
CACHE_TTL = 300          # 5 minutes for devices
USER_CACHE_TTL = 30      # 30 seconds for users (frequent role/perm changes)
MESSAGE_DEDUP_TTL = 5   # 5 seconds for message deduplication
last_cleanup = 0
CLEANUP_INTERVAL = 600  # 10 minutes

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    fixing_devices = set()  # Track devices currently being re-configured
    @staticmethod
    async def get_cached_device(ip):
        """Get device from cache or database — awaits DB lookup so event loop stays free."""
        now = time.time()
        if ip in device_cache:
            dev, timestamp = device_cache[ip]
            if now - timestamp < CACHE_TTL:
                return dev
        # Cache miss or expired — run blocking DB query in thread pool
        dev = await asyncio.to_thread(db_device.query_device_by_ip, ip)
        if dev:
            device_cache[ip] = (dev, now)
        return dev

    @staticmethod
    async def get_cached_users(dev_id, opts):
        """Get users from cache or router API — awaits so event loop stays free."""
        now = time.time()
        if dev_id in user_cache:
            users, timestamp = user_cache[dev_id]
            if now - timestamp < USER_CACHE_TTL:
                return users
        # Cache miss — run blocking API call in thread pool
        users = await asyncio.to_thread(util.get_local_users, opts)
        if users:
            user_cache[dev_id] = (users, now)
        return users or []
    
    @staticmethod
    def is_duplicate_message(addr, message):
        """Check if message is duplicate within dedup window.
        Safe without a lock — asyncio event loop is single-threaded."""
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
        """Periodic cache cleanup — no lock needed (single-threaded event loop)."""
        global last_cleanup
        now = time.time()
        if now - last_cleanup > CLEANUP_INTERVAL:
            last_cleanup = now
            device_cutoff = now - CACHE_TTL
            user_cutoff = now - USER_CACHE_TTL
            message_cutoff = now - MESSAGE_DEDUP_TTL
            for ip in list(device_cache.keys()):
                if device_cache[ip][1] <= device_cutoff:
                    del device_cache[ip]
            for dev_id in list(user_cache.keys()):
                if user_cache[dev_id][1] <= user_cutoff:
                    del user_cache[dev_id]
            for key in list(message_cache.keys()):
                if message_cache[key] <= message_cutoff:
                    del message_cache[key]
    # Pre-compiled regex patterns for better performance
    DEVICE_ID_REGEX = re.compile(r'(.*),?(info.*|warning|critical|error) mikrowizard(\d+):.*')
    LOGIN_REGEX = re.compile(r"user (.*) logged (in|out) from (..*)via.(.*)")
    LOGIN_FAILURE_REGEX = re.compile(r"login failure for user (.*) from (..*)via.(.*)")
    REBOOT_REGEX = re.compile(r'system,error,critical mikrowizard\d+: (.*)')
    SYSTEM_INFO_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (winbox-\d.{1,3}\d\/.*\(winbox\)|mac-msg\(winbox\)|tcp-msg\(winbox\)|ssh|telnet|api|api-ssl|console|.*\/web|ftp|www-ssl).*:(.*)@(.*) \((.*)\)")
    BUGGED_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by  \((.*)\)")
    FALLBACK_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (.*)")
    LINK_REGEX = re.compile(r"interface,info mikrowizard\d+: (.*) link (down|up).*")
    DHCP_REGEX = re.compile(r'dhcp,.* mikrowizard\d+: (.*)')
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

    async def _fix_device_syslog(self, dev):
        """Background task to fix device syslog configuration"""
        dev_id = dev.id
        ip = dev.ip
        
        if dev_id in self.fixing_devices:
            return
            
        self.fixing_devices.add(dev_id)
        try:
            log.warning(f"Starting background syslog reconfiguration for {ip} (ID: {dev_id})...")
            # Run the synchronous check_syslog_config in a thread
            result = await asyncio.to_thread(util.check_syslog_config, dev, None, True)
            if result:
                log.warning(f"Successfully re-configured syslog for {ip}")
                # Update cache to reflect that it might be fixed (optional, device ID mismatch will stop anyway)
            else:
                log.error(f"Failed to re-configure syslog for {ip}")
        except Exception as e:
            log.error(f"Error during syslog reconfiguration for {ip}: {e}")
        finally:
            # Wait a bit before allowing another fix attempt to avoid spamming the router
            await asyncio.sleep(30)
            self.fixing_devices.discard(dev_id)

    def datagram_received(self, data, addr):
        """Called when a datagram is received"""
        asyncio.create_task(self.handle_log(data, addr))

    async def handle_log(self, data, addr):
        try:
            message = data.strip().decode('utf-8', errors='ignore')

            # Check for duplicate messages
            if self.is_duplicate_message(addr, message):
                return

            if os.getenv("DEV_MODE") == "true":
                log.warning(f"Received syslog message from {addr[0]}: {message}")
            ts = int(time.time())

            # Periodic non-blocking cache cleanup
            self.cleanup_cache_if_needed()

            # Await async cache lookup (DB call runs in thread pool on cache miss)
            dev = await self.get_cached_device(addr[0])
            if not dev:
                return

            info = self.safe_extract_info(self.DEVICE_ID_REGEX, message, 3)
            if not info:
                return

            try:
                device_id = int(info[2])
                if dev.id != device_id:
                    if dev.id not in self.fixing_devices:
                        log.error(f"Device id mismatch for ip: {addr[0]} (DB ID: {dev.id}, Syslog ID: {device_id}). Triggering fix...")
                        force_syslog = await asyncio.to_thread(db_sysconfig.get_sysconfig, 'force_syslog')
                        if force_syslog == "True":
                            asyncio.create_task(self._fix_device_syslog(dev))
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
            
        if ISPRO:
            # Wrap blocking pro regex engine in thread pool
            await asyncio.to_thread(syslog_regex_pro.process_custom_syslog_regex, dev, message)

        if 'mikrowizard' in message and 'via api' not in message:
            if 'system,info,account' in message:
                # Delay processing by 1 second to avoid race condition with RADIUS accounting inserts.
                await asyncio.sleep(1)

                login_info = self.safe_extract_info(self.LOGIN_REGEX, message, 4)
                if login_info:
                    try:
                        if users is None:
                            # Await async user lookup
                            users = await self.get_cached_users(dev.id, opts)
                        msg = 'local' if login_info[0] in users else 'radius'
                        if 'logged in' in message and 'via api' not in message:
                            await asyncio.to_thread(
                                db_AA.Auth.add_log, dev.id, 'loggedin',
                                login_info[0], login_info[2], login_info[3],
                                timestamp=ts, message=msg
                            )
                        elif 'logged out' in message and login_info[0] in users:
                            await asyncio.to_thread(
                                db_AA.Auth.add_log, dev.id, 'loggedout',
                                login_info[0], login_info[2], login_info[3],
                                timestamp=ts, message=msg
                            )
                    except Exception as e:
                        log.error(f"Error processing login: {e}")
                        log.error(message)
            elif 'system,error,critical' in message:
                if "login failure" in message:
                    failure_info = self.safe_extract_info(self.LOGIN_FAILURE_REGEX, message, 3)
                    if failure_info:
                        if users is None:
                            users = await self.get_cached_users(dev.id, opts)
                        msg = 'local' if failure_info[0] in users else 'radius'
                        await asyncio.to_thread(
                            db_AA.Auth.add_log, dev.id, 'failed',
                            failure_info[0], failure_info[1], failure_info[2],
                            timestamp=ts, message=msg
                        )
                elif "rebooted" in message:
                    reboot_info = self.safe_extract_info(self.REBOOT_REGEX, message, 1)
                    if reboot_info:
                        await asyncio.to_thread(
                            db_events.state_event, dev.id, "syslog",
                            "Unexpected Reboot", "Critical", 1, reboot_info[0]
                        )

            elif 'system,info mikrowizard' in message:
                if ISPRO:
                    await asyncio.to_thread(utilpro.do_pro, "syslog", False, dev, message)

                system_info = self.safe_extract_info(self.SYSTEM_INFO_REGEX, message, 6)
                if system_info:
                    address = system_info[4].split('/')
                    ctype = self._determine_connection_type(system_info[2], address)
                    await asyncio.to_thread(
                        db_AA.Account.add_log, dev.id, system_info[0],
                        system_info[1], system_info[3], message, ctype,
                        address[0], system_info[5]
                    )
                else:
                    bugged_info = self.safe_extract_info(self.BUGGED_REGEX, message, 3)
                    if bugged_info:
                        await asyncio.to_thread(
                            db_AA.Account.add_log, dev.id, bugged_info[0],
                            bugged_info[1], "Unknown (Mikrotik Bug)", message,
                            config=bugged_info[2]
                        )
                    elif "rebooted" in message:
                        await asyncio.to_thread(
                            db_events.state_event, dev.id, "syslog",
                            "Router Rebooted", "info", 1, info[0]
                        )
                    elif "resetting system configuration" in message:
                        await asyncio.to_thread(
                            db_events.state_event, dev.id, "syslog",
                            "Router reset", "info", 1, info[0]
                        )
                    else:
                        fallback_info = self.safe_extract_info(self.FALLBACK_REGEX, message, 3)
                        if fallback_info:
                            await asyncio.to_thread(
                                db_AA.Account.add_log, dev.id, fallback_info[0],
                                fallback_info[1], fallback_info[2], message
                            )
            elif 'interface,info mikrowizard' in message:
                events = await asyncio.to_thread(
                    lambda: list(db_events.get_events_by_src_and_status("syslog", 0, dev.id).dicts())
                )
                if "link down" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        await asyncio.to_thread(
                            db_events.state_event, dev.id, "syslog",
                            f"Link Down: {link_info[0]}", "Warning", 0,
                            f"Link is down for {link_info[0]}"
                        )
                elif "link up" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        await asyncio.to_thread(
                            util.check_or_fix_event, events, 'state',
                            f"Link Down: {link_info[0]}"
                        )
            elif any(term in message for term in ["dhcp,info", "dhcp,critical", "dhcp,warning", "dhcp,error"]):
                client_type = 'client' if " dhcp-client on" in message else 'server'
                
                dhcp_info = self.safe_extract_info(self.DHCP_REGEX, message, 1)
                if not dhcp_info:
                    return
                    
                # Determine database level and status
                level = "info"
                status = 1  # Default to archived/silent
                
                if "dhcp,warning" in message:
                    level = "Warning"
                elif "dhcp,critical" in message:
                    level = "Critical"
                elif "dhcp,error" in message:
                    level = "Error"

                # Check for critical errors that should hit the monitoring wall (status=0)
                if "pool" in message and "empty" in message:
                    detail = "dhcp pool empty"
                    level = "Warning"
                    status = 0
                elif "std failure: timeout" in message:
                    detail = "dhcp resource timeout"
                    level = "Error"
                    status = 0
                else:
                    # Generic detail for history/logs
                    if client_type == 'server':
                        if "deassigned" in message:
                            detail = "dhcp deassigned"
                        elif "assigned" in message:
                            detail = "dhcp assigned"
                        else:
                            detail = "dhcp server event"
                    else:
                        detail = "dhcp client event"

                # Store the event
                await asyncio.to_thread(
                    db_events.state_event, dev.id, "syslog", detail, level, status, dhcp_info[0]
                )
            elif "wireless,info mikrowizard" in message:
                if ISPRO:
                    await asyncio.to_thread(utilpro.wireless_syslog_event, dev, message)
                else:
                    wireless_info = self.safe_extract_info(self.WIRELESS_REGEX, message, 3)
                    if wireless_info:
                        strength = wireless_info[4] if len(wireless_info) > 4 else ""
                        await asyncio.to_thread(
                            db_events.state_event, dev.id, "syslog", "wireless client", "info", 1,
                            f"{wireless_info[0]} {wireless_info[1]} {wireless_info[2]} {wireless_info[3]} {strength}"
                        )
            else:
                if os.getenv("DEV_MODE") == "true":
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
