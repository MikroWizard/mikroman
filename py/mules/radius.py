#!/usr/bin/python
# -*- coding: utf-8 -*-

# radius.py: independent worker process as a radius server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from libs.db.db_device import Devices, EXCLUDED, database
from libs.db import db_sysconfig
import logging
import time
import asyncio
import threading
import os
from concurrent.futures import ThreadPoolExecutor

import logging
from pyrad.dictionary import Dictionary
from pyrad.server_async import ServerAsync
from pyrad.packet import AccessAccept,AccessReject
from pyrad.server import RemoteHost
from libs.mschap3 import mschap,mppe
from libs.db import db,db_user_group_perm,db_device,db_groups,db_device,db_AA,db_sysconfig,db_events
import re
from libs.db.db import release_db_connection
from libs.util import FourcePermToRouter
from libs import logsetup
from libs import radius_ma
from libs import radius_throttle
from libs import login_throttle
from libs.red import RedisDB
import config

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except:
    pass
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

logsetup.init_logging()   # same log output in the free tier (Pro gets it via libs.webutil)
log = logging.getLogger("Radius")

# Older versions wrote a root-DEBUG pyrad.log here (2.0.0 Free); logging is configured by
# logsetup above. A leftover file from those versions is removed in main().
LEGACY_LOG = "pyrad.log"

# Thread pool for blocking RADIUS operations (DB lookups + RouterOS API calls).
# Small deployments: 4 workers is sufficient (RADIUS bursts are rare and short-lived).
# Enterprise (500+ devices with force_perms): increase to 8-12 workers.
_radius_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="radius-worker")

class RadServer(ServerAsync):

    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                              debug=True)
        # UDP packet deduplication cache: {key: timestamp}
        self._dedup_cache = {}
        self._dedup_ttl = 5  # seconds
        self._dedup_cleanup_counter = 0
        # Track proxy-authenticated users: {(username, devip): timestamp}
        self._proxy_users = {}
        # Track proxy session IDs so we don't log their logouts: {sessionid: timestamp}
        self._proxy_sessions = {}
        # Raw replies of recent Access-Requests: a retransmission (same key within the dedup
        # TTL) gets the same reply again instead of being dropped (RFC 5080 2.2.2).
        # {key: (timestamp, raw_bytes)}; written from pool threads, so guarded by a lock.
        self._reply_cache = {}
        self._reply_lock = threading.Lock()
        # Inbound Message-Authenticator mode (sysconfig radius_require_message_auth)
        self.ma_mode = radius_ma.MODE_VERIFY
        self.nas_tracker = radius_ma.NasTracker()
        self._ma_warned = {}
        # failed-login throttling per (UDP source, user) and per source; settings in main()
        self.throttle = radius_throttle.FailThrottle()
        self._redis = None        # lazy, only used to read admin unlocks
        # Settings page values are re-read at most once a minute (in the pool), so changes
        # apply without restarting the RADIUS service
        self._settings_loaded = time.time()
        self._settings_reloading = False
        # open lockout events this process created: {(detail, devid): (kind, source, user, until)}
        self._lockout_open = {}
        self._lockout_lock = threading.Lock()

    def _maybe_reload_settings(self):
        """Schedule a settings reload when due. Cheap; never blocks the event loop."""
        if self._settings_reloading or time.time() - self._settings_loaded < SETTINGS_REFRESH:
            return
        self._settings_reloading = True
        try:
            asyncio.get_event_loop().run_in_executor(_radius_executor, self._reload_settings)
        except Exception:
            self._settings_reloading = False

    @release_db_connection
    def _reload_settings(self):
        """Apply the RADIUS security settings (pool thread). Errors keep the current values."""
        try:
            _apply_settings(self)
        except Exception as e:
            log.warning("RADIUS settings reload failed: %s" % e)
        finally:
            self._settings_loaded = time.time()
            self._settings_reloading = False

    @staticmethod
    def CreateReplyPacket(pkt, **attributes):
        # Replies to Access-Request carry Message-Authenticator first (RFC 3579 / BlastRADIUS).
        # Valid for routers with require-message-auth on or off; see libs/radius_ma.py.
        return radius_ma.create_access_reply(pkt, **attributes)

    def _send_auth_reply(self, protocol, reply, addr, cache_key=None):
        """Send an Access reply and remember its bytes for retransmissions."""
        raw = reply.ReplyPacket()
        protocol.transport.sendto(raw, addr)   # UDP sendto, same as protocol.send_response
        if cache_key is not None:
            with self._reply_lock:
                self._reply_cache[cache_key] = (time.time(), raw)

    def _admin_unlocked(self, source, username):
        """An admin unlocked this user / source after the block started (panel "unlock" or
        py/unlock_logins.py, signalled through Redis). Only called while blocked; any error
        keeps the block (it still expires by itself)."""
        try:
            if self._redis is None:
                self._redis = RedisDB({}).r
            since = login_throttle.radius_unlocked_since(self._redis, source, username)
            # +1 s: the unlock time is stored rounded; blocks from the same moment are released too
            if since and self.throttle.release(source, username, since + 1.0):
                log.warning("RADIUS: block of %s (user %s) released by an admin unlock", source, username)
                asyncio.get_event_loop().run_in_executor(
                    _radius_executor, self._resolve_lockout_events,
                    [LOCKOUT_USER + _safe_name(username), LOCKOUT_SOURCE + str(source)])
                return not self.throttle.blocked(source, username)
        except Exception:
            pass
        return False

    def _auth_failed(self, addr, username, dev=None):
        """Count a failed login for throttling; when a lockout starts, log it and add a
        Warning event on the router (Monitoring wall, Pro alerts). Never raises."""
        try:
            started = self.throttle.failure(addr[0], username)
            if started:
                log.warning("RADIUS: too many failed logins from %s (user %s), refusing for %ss",
                            addr[0], username, self.throttle.block)
                if dev is not None:
                    self._lockout_events(dev.id, addr[0], username, started)
        except Exception:
            pass

    def _lockout_events(self, devid, source, username, kinds):
        """One open event per locked user / source on the router (de-duplicated by detail)."""
        t = self.throttle
        user = _safe_name(username)
        for kind in kinds:
            try:
                if kind == "user":
                    db_events.state_event(
                        devid, LOCKOUT_SRC, LOCKOUT_USER + user, "Warning", 0,
                        "More than {} failed logins for '{}' from {} within {}s; its logins are refused "
                        "for {}s. Unlock: User Management > Locked Logins.".format(
                            t.limit, user, source, t.window, t.block))
                else:
                    db_events.state_event(
                        devid, LOCKOUT_SRC, LOCKOUT_SOURCE + str(source), "Warning", 0,
                        "More than {} failed logins from {} (any user) within {}s; all its logins are "
                        "refused for {}s. Unlock: User Management > Locked Logins.".format(
                            t.source_limit, source, t.window, t.block))
                detail = (LOCKOUT_USER + user) if kind == "user" else (LOCKOUT_SOURCE + str(source))
                with self._lockout_lock:
                    self._lockout_open[(detail, devid)] = (kind, source, username, time.time() + t.block)
            except Exception as e:
                log.warning("Could not add lockout event: %s" % e)

    @release_db_connection
    def _sweep_lockout_events(self):
        """Close lockout events whose block is over: expired, released by an admin unlock (even
        when the router sends no further login) or cleared by a successful login. Pool thread,
        called by the maintenance timer. Never raises."""
        try:
            now = time.time()
            with self._lockout_lock:
                items = list(self._lockout_open.items())
            done = []
            for (detail, devid), (kind, source, username, until) in items:
                if self._redis is None:
                    try:
                        self._redis = RedisDB({}).r
                    except Exception:
                        pass
                if self._redis is not None:
                    since = login_throttle.radius_unlocked_since(self._redis, source, username)
                    if since:
                        self.throttle.release(source, username, since + 1.0)
                if until <= now or not self.throttle.is_active(kind, source, username, now):
                    done.append((detail, devid))
            for detail, devid in done:
                self._resolve_lockout_events([detail], devid)
                with self._lockout_lock:
                    self._lockout_open.pop((detail, devid), None)
        except Exception as e:
            log.warning("Lockout event sweep failed: %s" % e)

    def _maintenance_tick(self, loop):
        """Every MAINTENANCE_SECONDS on the event loop: close finished lockout events and reload
        settings, both in the pool (works without RADIUS traffic)."""
        try:
            if self._lockout_open:
                loop.run_in_executor(_radius_executor, self._sweep_lockout_events)
            self._maybe_reload_settings()
        except Exception as e:
            log.warning("RADIUS maintenance failed: %s" % e)
        finally:
            loop.call_later(MAINTENANCE_SECONDS, self._maintenance_tick, loop)

    @release_db_connection
    def _resolve_lockout_events(self, details, devid=None):
        """Close open lockout events (after a successful login or an admin unlock)."""
        try:
            ev = db_events.Events
            q = ev.select(ev.id).where(ev.src == LOCKOUT_SRC, ev.status == False, ev.detail << list(details))
            if devid is not None:
                q = q.where(ev.devid == devid)
            for row in list(q):
                db_events.fix_event(row.id)
        except Exception as e:
            log.warning("Could not resolve lockout events: %s" % e)

    def _warn_once(self, key, msg, *args):
        """Warn at most once per minute per key (a misconfigured router retries a lot)."""
        now = time.time()
        if now - self._ma_warned.get(key, 0) >= 60:
            self._ma_warned[key] = now
            log.warning(msg, *args)

    def _is_duplicate(self, cache_key):
        """Check if a packet with this key was already processed within TTL.
        Returns True if duplicate, False if new (and registers it)."""
        now = time.time()
        # Periodic cleanup every 50 packets
        self._dedup_cleanup_counter += 1
        if self._dedup_cleanup_counter >= 50:
            self._dedup_cleanup_counter = 0
            cutoff = now - self._dedup_ttl
            self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v > cutoff}
            with self._reply_lock:
                self._reply_cache = {k: v for k, v in self._reply_cache.items() if v[0] > cutoff}

        if cache_key in self._dedup_cache:
            if now - self._dedup_cache[cache_key] < self._dedup_ttl:
                return True
        self._dedup_cache[cache_key] = now
        return False
    def verifyMsChapV2(self,pkt,userpwd,group,nthash):

        ms_chap_response = pkt['MS-CHAP2-Response'][0]
        authenticator_challenge = pkt['MS-CHAP-Challenge'][0]
        
        if len(ms_chap_response)!=50:
            raise Exception("Invalid MSCHAPV2-Response attribute length")

        nt_response = ms_chap_response[26:50]
        peer_challenge = ms_chap_response[2:18]
        _user_name = pkt.get(1)[0]
        try:
            nt_resp = mschap.generate_nt_response_mschap2(
                authenticator_challenge,
                peer_challenge,
                _user_name,
                userpwd,
                nthash
            )
            if nt_resp == nt_response:
                auth_resp = mschap.generate_authenticator_response(
                    userpwd,
                    nt_response,
                    peer_challenge,
                    authenticator_challenge,
                    _user_name,
                    nthash
                )
                mppeSendKey, mppeRecvKey = mppe.mppe_chap2_gen_keys(userpwd, nt_response,nthash)

                if group:
                    reply = self.CreateReplyPacket(pkt, **{
                        "MS-CHAP2-Success": auth_resp.encode(),
                        "Mikrotik-Group": group,
                    })
                else:
                    reply = self.CreateReplyPacket(pkt, **{
                        "MS-CHAP2-Success": auth_resp.encode(),
                    })
                reply.code = AccessAccept
                return reply
            
            else:
                return False
        finally:
            # Clear sensitive variables from memory
            if 'mppeSendKey' in locals():
                del mppeSendKey
            if 'mppeRecvKey' in locals():
                del mppeRecvKey

    def send_auth_reject(self,protocol,pkt,addr,cache_key=None):
        reply = self.CreateReplyPacket(pkt, **{
        })
        reply.code = AccessReject
        reply.error_msg = "User password wrong" 
        #log failed attempts
        self._send_auth_reply(protocol, reply, addr, cache_key)

    def handle_auth_packet(self, protocol, pkt, addr):
        """Dispatcher: validate and dedup on the event loop, then hand off
        all blocking work (DB + RouterOS API) to the thread pool.

        NOTE: pyrad calls this synchronously from datagram_received, so it
        cannot be async def.  We use loop.run_in_executor() to offload without
        blocking the event loop thread."""
        try:
            self._maybe_reload_settings()
            # Message-Authenticator check first (cheap, on the event loop). Default mode only
            # rejects a Message-Authenticator that is present and wrong (wrong shared secret
            # or modified packet: such a login already fails today).
            ma_status = radius_ma.check_request(pkt, self.ma_mode, self.nas_tracker)
            if ma_status != radius_ma.ACCEPT:
                if ma_status == radius_ma.DROP_INVALID:
                    self._warn_once((addr[0], ma_status),
                                    "Dropping Access-Request from %s: invalid Message-Authenticator "
                                    "(check the RADIUS secret on the router)", addr[0])
                else:
                    self._warn_once((addr[0], ma_status),
                                    "Dropping Access-Request from %s: missing Message-Authenticator "
                                    "(radius_require_message_auth=%s)", addr[0], self.ma_mode)
                return

            tz = int(time.time())
            username = pkt['User-Name'][0]
            userip = pkt['Calling-Station-Id'][0]
            devip = pkt['NAS-IP-Address'][0]

            # Too many failed logins from this source (for this user): immediate Reject,
            # the password is not checked, so guessing gets no answer.
            if self.throttle.blocked(addr[0], username) and not self._admin_unlocked(addr[0], username):
                self._warn_once((addr[0], 'throttle'),
                                "RADIUS logins from %s temporarily refused after repeated failures", addr[0])
                self.send_auth_reject(protocol, pkt, addr)
                return

            # Fast in-memory dedup — stays on the event loop thread
            auth_key = ('auth', username, userip, devip, pkt.id)
            if self._is_duplicate(auth_key):
                with self._reply_lock:
                    cached = self._reply_cache.get(auth_key)
                if cached:
                    # retransmission of a request we already answered: same reply again
                    protocol.transport.sendto(cached[1], addr)
                    log.info("Re-sent reply for retransmitted auth packet of %s (id: %s)" % (username, pkt.id))
                else:
                    log.info("Dropping duplicate auth packet for %s (id: %s)" % (username, pkt.id))
                return

            # Offload all DB + network work to thread pool
            loop = asyncio.get_event_loop()
            loop.run_in_executor(
                _radius_executor,
                self._handle_auth_blocking,
                protocol, pkt, addr, username, userip, devip, tz, auth_key
            )
        except Exception as e:
            log.error("Auth dispatch error: %s", str(e))
            self.send_auth_reject(protocol, pkt, addr)

    @release_db_connection   # pool thread: give the DB connection back after every request
    def _handle_auth_blocking(self, protocol, pkt, addr, username, userip, devip, tz, auth_key=None):
        """Runs in thread pool. Performs all DB lookups and RouterOS API calls."""
        try:
            dev = db_device.query_device_by_ip(devip)
            if not dev:
                self.send_auth_reject(protocol, pkt, addr, auth_key)
                return

            u = db.get_user_by_username(username)
            if not u or u.role == 'disabled':
                self._auth_failed(addr, username, dev)
                self.send_auth_reject(protocol, pkt, addr, auth_key)
                db_AA.Auth.add_log(dev.id, 'failed', username, userip,
                                   by=None, sessionid=None, timestamp=tz,
                                   message="User Not Exist")
                return

            if not dev:
                self.send_auth_reject(protocol, pkt, addr, auth_key)
                db_AA.Auth.add_log(dev.id, 'failed', u.username, userip,
                                   by=None, sessionid=None, timestamp=tz,
                                   message="Device Not Exist")
                return

            force_perms = db_sysconfig.get_sysconfig('force_perms') == "True"
            perm = None
            if force_perms:
                dev_groups = db_groups.devgroups(dev.id)
                dev_groups_ids = [group.id for group in dev_groups]
                dev_groups_ids.append(1)
                if dev and len(dev_groups_ids) > 0:
                    perm = db_user_group_perm.DevUserGroupPermRel.query_permission_by_user_and_device_group(
                        u.id, dev_groups_ids
                    )
                    # No group relation: reject as before. The router permission push itself
                    # (FourcePermToRouter) now runs only after the password matched, so an
                    # unauthenticated packet can no longer make MikroWizard log in to a router.
                    if len(list(perm)) == 0:
                        self._auth_failed(addr, username, dev)
                        self.send_auth_reject(protocol, pkt, addr, auth_key)
                        db_AA.Auth.add_log(dev.id, 'failed', u.username, userip,
                                           by=None, sessionid=None, timestamp=tz,
                                           message="Unable to verify group")
                        return

            nthash = u.hash
            tnthash = None
            is_proxy = False
            if ISPRO:
                nthash, tnthash = utilpro.GetNThash(u)

            reply = None
            matched_hash_type = None

            if tnthash:
                if force_perms:
                    reply = self.verifyMsChapV2(pkt, "password", perm[0].perm_id.name, tnthash)
                else:
                    reply = self.verifyMsChapV2(pkt, "password", False, tnthash)
                if reply and reply.code == AccessAccept:
                    matched_hash_type = 'pth'

            if not reply or reply.code != AccessAccept:
                if nthash:
                    if force_perms:
                        reply = self.verifyMsChapV2(pkt, "password", perm[0].perm_id.name, nthash)
                    else:
                        reply = self.verifyMsChapV2(pkt, "password", False, nthash)
                    if reply and reply.code == AccessAccept:
                        matched_hash_type = 'normal'

            if reply and reply.code == AccessAccept:
                # Password matched: push the user's group permissions to the router (same
                # call and same reject as before, only after verification instead of before).
                if force_perms:
                    # Critical blocking call — runs in the thread pool
                    if not FourcePermToRouter(dev, perm):
                        self.send_auth_reject(protocol, pkt, addr, auth_key)
                        db_AA.Auth.add_log(dev.id, 'failed', u.username, userip,
                                           by=None, sessionid=None, timestamp=tz,
                                           message="Unable to verify group")
                        return

                if ISPRO:
                    is_proxy = (matched_hash_type == 'pth')
                    userip, respro = utilpro.verfyRadius(u, userip, is_proxy)
                    if not respro:
                        db_AA.Auth.add_log(dev.id, 'failed', u.username, userip,
                                           by=None, sessionid=None, timestamp=tz,
                                           message="IP not allowed: {}".format(userip))
                        self.send_auth_reject(protocol, pkt, addr, auth_key)
                        return

                    if is_proxy:
                        log.info("web-proxy User %s logged in from %s" % (u.username, userip))
                        proxy_sid = utilpro.resolve_proxy_session(tnthash) if (ISPRO and hasattr(utilpro, 'resolve_proxy_session')) else None
                        try:
                            db_AA.Auth.add_log(dev.id, 'proxy', u.username, userip,
                                               by="proxy", sessionid=proxy_sid, timestamp=tz,
                                               message="proxy login")
                        except Exception as log_err:
                            log.error("Failed to add proxy auth log: %s", str(log_err))
                        self._proxy_users[(u.username, devip)] = tz

                # UDP sendto is thread-safe
                if self.throttle.success(addr[0], username):
                    detail = LOCKOUT_USER + _safe_name(username)
                    self._resolve_lockout_events([detail], dev.id)
                    with self._lockout_lock:
                        self._lockout_open.pop((detail, dev.id), None)
                self._send_auth_reply(protocol, reply, addr, auth_key)
                return True

            self._auth_failed(addr, username, dev)
            db_AA.Auth.add_log(dev.id, 'failed', u.username, userip,
                               by=None, sessionid=None, timestamp=tz,
                               message="Wrong Password")
            self.send_auth_reject(protocol, pkt, addr, auth_key)
        except Exception as e:
            log.error("Auth worker error: %s", str(e))
            self.send_auth_reject(protocol, pkt, addr, auth_key)

    def handle_acct_packet(self, protocol, pkt, addr):
        """Dispatcher: offload DB accounting writes to thread pool."""
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            _radius_executor,
            self._handle_acct_blocking,
            protocol, pkt, addr
        )

    @release_db_connection
    def _handle_acct_blocking(self, protocol, pkt, addr):
        """Original accounting logic, runs in thread pool."""
        try:
            ts = int(time.time())
            dev_ip = pkt['NAS-IP-Address'][0]
            dev = db_device.query_device_by_ip(dev_ip)
            type = pkt['Acct-Status-Type'][0]
            if not dev:                      # query_device_by_ip returns False when unknown
                log.warning("Accounting %s from unknown router %s ignored" % (type, dev_ip))
                reply = self.CreateReplyPacket(pkt)
                protocol.send_response(reply, addr)
                return
            if type in ('Accounting-On', 'Accounting-Off'):
                # The router (re)started or stops accounting (RFC 2866): every session it
                # had is over and will never get its own Stop. These packets carry no
                # User-Name.
                closed = db_AA.Auth.close_device_radius_sessions(dev.id, ts)
                log.info("Router %s sent %s: %d open login session(s) closed" % (dev_ip, type, closed))
                reply = self.CreateReplyPacket(pkt)
                protocol.send_response(reply, addr)
                return
            if type not in ('Start', 'Stop'):
                reply = self.CreateReplyPacket(pkt)       # Interim-Update / Alive: nothing to log
                protocol.send_response(reply, addr)
                return
            user = pkt['User-Name'][0]
            userip = pkt['Calling-Station-Id'][0]
            sessionid = pkt['Acct-Session-Id'][0]
            # Dedup: drop retransmitted accounting packets
            acct_key = ('acct', sessionid, type)
            if self._is_duplicate(acct_key):
                log.info("Dropping duplicate acct packet for %s (session %s, type %s)" % (user, sessionid, type))
                reply = self.CreateReplyPacket(pkt)
                protocol.send_response(reply, addr)
                return
            if type == 'Start':
                log.info("User %s logged in from %s" % (user, userip))
                proxy_key = (user, dev_ip)
                acct_by = None
                if proxy_key in self._proxy_users:
                    if ts - self._proxy_users[proxy_key] < 30:
                        acct_by = 'MW-proxy'
                    del self._proxy_users[proxy_key]

                if acct_by == 'MW-proxy':
                    self._proxy_sessions[sessionid] = ts
                    self._proxy_sessions = {k: v for k, v in self._proxy_sessions.items() if ts - v < 86400}
                else:
                    db_AA.Auth.add_log(dev.id, 'loggedin', user, userip, acct_by, timestamp=ts, sessionid=sessionid)
            elif type == 'Stop':
                log.info("User %s logged out from %s" % (user, userip))
                is_proxy_session = False
                if sessionid in self._proxy_sessions:
                    is_proxy_session = True
                    del self._proxy_sessions[sessionid]
                if not is_proxy_session:
                    db_AA.Auth.add_log(dev.id, 'loggedout', user, userip, None, timestamp=ts, sessionid=sessionid)
        except Exception as e:
            log.error("Error in accounting: ")
            log.error(e)
            log.error("Received an accounting request")
            log.error("Attributes: ")
            log.error(pkt.keys())
        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, pkt, addr):

        log.error("Received an coa request")
        log.error("Attributes: ")
        for attr in pkt.keys():
            log.error("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):

        log.error("Received an disconnect request")
        log.error("Attributes: ")
        for attr in pkt.keys():
            log.error("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        protocol.send_response(reply, addr)



SETTINGS_REFRESH = 60     # seconds between settings reloads

# RADIUS failed-login lockout events (Monitoring wall)
MAINTENANCE_SECONDS = 60
LOCKOUT_SRC = "RADIUS"
LOCKOUT_USER = "RADIUS login lockout: "
LOCKOUT_SOURCE = "RADIUS login lockout: source "
_NAME_RE = re.compile(r"[^\w.@+\-]")


@release_db_connection
def _resolve_stale_lockout_events():
    """At start: close RADIUS lockout events left open by the previous run (its in-memory
    blocks are gone, so those lockouts no longer apply). Never raises."""
    try:
        ev = db_events.Events
        q = ev.select(ev.id).where(ev.src == LOCKOUT_SRC, ev.status == False,
                                   ev.detail.startswith(LOCKOUT_USER))
        n = 0
        for row in list(q):
            db_events.fix_event(row.id)
            n += 1
        if n:
            log.warning("Closed %d RADIUS lockout event(s) left open by the previous run" % n)
    except Exception as e:
        log.warning("Could not close old lockout events: %s" % e)


def _safe_name(username):
    """User-Name is attacker controlled: keep a short, printable form for event texts."""
    return _NAME_RE.sub("?", str(username or ""))[:64] or "?"


def _apply_settings(server):
    """Message-Authenticator mode and failed-login limits from sysconfig (Settings page).
    Limits are changed in place, so current counters and blocks are kept."""
    mode = radius_ma.parse_mode(db_sysconfig.get_sysconfig('radius_require_message_auth'))
    if mode != server.ma_mode:
        log.warning("RADIUS server: inbound Message-Authenticator check mode '%s'" % mode)
    server.ma_mode = mode
    t = server.throttle
    t.limit = _int_setting('radius_fail_limit', 10)
    t.window = _int_setting('radius_fail_window', 300) or 300
    t.block = _int_setting('radius_block_seconds', 300) or 300
    t.source_limit = _int_setting('radius_fail_limit_source', 100)


def _int_setting(key, default):
    """Integer sysconfig value, default when missing or invalid (0 disables a limit)."""
    try:
        v = db_sysconfig.get_sysconfig(key)
        return default if v in (None, "") else int(v)
    except Exception:
        return default


def _remove_legacy_log():
    """2.0.0 Free wrote a root-DEBUG pyrad.log (could contain device API credentials and the
    RADIUS secret). Updates copy files over /app but never delete, so remove it once."""
    try:
        if os.path.isfile(LEGACY_LOG):
            os.remove(LEGACY_LOG)
            log.warning("Removed legacy %s written by older versions" % os.path.abspath(LEGACY_LOG))
    except Exception as e:
        log.warning("Could not remove legacy %s: %s" % (LEGACY_LOG, e))


def main():
    loop = None
    server = None
    
    try:
        # create server and read dictionary
        loop = asyncio.get_event_loop()
        server = RadServer(loop=loop, dictionary=Dictionary('py/libs/raddic/dictionary'))
        secret = db_sysconfig.get_sysconfig('rad_secret')
        _apply_settings(server)
        _remove_legacy_log()
        log.warning("RADIUS server: replies carry Message-Authenticator, inbound check mode '%s'" % server.ma_mode)
        server.hosts["0.0.0.0"] = RemoteHost("0.0.0.0",
                                               secret.encode(),
                                               "localhost")

        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(enable_auth=True,
                                             enable_acct=True,
                                             enable_coa=False,
                                             addresses=['0.0.0.0'])))
        # lockout blocks live in memory only: events left open by an earlier run are over
        _resolve_stale_lockout_events()
        loop.call_later(MAINTENANCE_SECONDS, server._maintenance_tick, loop)
        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt:
            pass

    except Exception as exc:
        log.error('Error: %s', exc)
    
    finally:
        # Ensure cleanup always happens
        if server:
            try:
                if loop and not loop.is_closed():
                    loop.run_until_complete(asyncio.ensure_future(
                        server.deinitialize_transports()))
            except Exception as cleanup_exc:
                log.error('Cleanup error: %s', cleanup_exc)
        
        if loop and not loop.is_closed():
            try:
                loop.close()
            except Exception:
                pass

    
if __name__ == '__main__':
    main()


