#!/usr/bin/python
# -*- coding: utf-8 -*-

# radius.py: independent worker process as a radius server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from libs.db.db_device import Devices,EXCLUDED,database
from libs.db import db_sysconfig
import logging
import time
import asyncio

import logging
from pyrad.dictionary import Dictionary
from pyrad.server_async import ServerAsync
from pyrad.packet import AccessAccept,AccessReject
from pyrad.server import RemoteHost
from libs.mschap3 import mschap,mppe
from libs.db import db,db_user_group_perm,db_device,db_groups,db_device,db_AA,db_sysconfig
from libs.util import FourcePermToRouter

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

log = logging.getLogger("Radius")

logging.basicConfig(filename="pyrad.log", level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")

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

    def send_auth_reject(self,protocol,pkt,addr):
        reply = self.CreateReplyPacket(pkt, **{
        })
        reply.code = AccessReject
        reply.error_msg = "User password wrong" 
        #log failed attempts
        protocol.send_response(reply, addr)

    def handle_auth_packet(self, protocol, pkt, addr):
        # log.error("Attributes: ")
        # for attr in pkt.keys():
        #     log.error("%s: %s" % (attr, pkt[attr]))
        try:
            tz=int(time.time())
            username = pkt['User-Name'][0]
            userip=pkt['Calling-Station-Id'][0]
            devip=pkt['NAS-IP-Address'][0]
            # Dedup: drop retransmitted auth packets
            auth_key = ('auth', username, userip, devip, pkt.id)
            if self._is_duplicate(auth_key):
                log.info("Dropping duplicate auth packet for %s (id: %s)" % (username, pkt.id))
                return
            dev=db_device.query_device_by_ip(devip)
            if not dev:
                self.send_auth_reject(protocol,pkt,addr)
                return
      
            u = db.get_user_by_username(username)
            if not u or u.role=='disabled':
                    self.send_auth_reject(protocol,pkt,addr)
                    db_AA.Auth.add_log(dev.id, 'failed',  username , userip , by=None,sessionid=None,timestamp=tz,message="User Not Exist")
                    return
            else:
                #get user permision related to device
                if not dev:
                    self.send_auth_reject(protocol, pkt, addr)
                    db_AA.Auth.add_log(dev.id, 'failed', u.username, userip, by=None, sessionid=None, timestamp=tz, message="Device Not Exist")
                    return
                force_perms=True if db_sysconfig.get_sysconfig('force_perms')=="True" else False
                if force_perms:
                    dev_groups=db_groups.devgroups(dev.id)
                    dev_groups_ids=[group.id for group in dev_groups]
                    dev_groups_ids.append(1)
                    res=False
                    if dev and len(dev_groups_ids)>0:
                        perm=db_user_group_perm.DevUserGroupPermRel.query_permission_by_user_and_device_group(u.id,dev_groups_ids)
                        res2=False
                        if len(list(perm))>0:
                            res2=FourcePermToRouter(dev,perm)
                        if not res2:
                            self.send_auth_reject(protocol,pkt,addr)
                            db_AA.Auth.add_log(dev.id, 'failed',  u.username , userip , by=None,sessionid=None,timestamp=tz,message="Unable to verify group")
                            return
                nthash=u.hash
                tnthash=None
                is_proxy = False
                if(ISPRO):
                    nthash, tnthash = utilpro.GetNThash(u)
                    
                    pass
                    pass
                
                reply = None
                matched_hash_type = None
                
                reply = None
                # Try tnthash
                if tnthash:
                    if force_perms:
                        reply = self.verifyMsChapV2(pkt, "password", perm[0].perm_id.name, tnthash)
                    else:
                        reply = self.verifyMsChapV2(pkt, "password", False, tnthash)
                    if reply and reply.code == AccessAccept:
                        matched_hash_type = 'pth'
                
                # If it failed try nthash 
                if not reply or reply.code != AccessAccept:
                    if nthash:
                        if force_perms:
                            reply = self.verifyMsChapV2(pkt, "password", perm[0].perm_id.name, nthash)
                        else:
                            reply = self.verifyMsChapV2(pkt, "password", False, nthash)
                        if reply and reply.code == AccessAccept:
                            matched_hash_type = 'normal'
                            
                if reply and reply.code == AccessAccept:
                    # Now that we know WHICH password matched, we can enforce IP restrictions correctly
                    if ISPRO:
                        is_proxy = (matched_hash_type == 'pth')
                        userip, respro = utilpro.verfyRadius(u, userip, is_proxy)
                        if not respro:
                            db_AA.Auth.add_log(dev.id, 'failed', u.username, userip, by=None, sessionid=None, timestamp=tz, message="IP not allowed: {}".format(userip))
                            self.send_auth_reject(protocol, pkt, addr)
                            return
                            
                        if is_proxy:
                            log.info("web-proxy User %s logged in from %s" % (u.username, userip))
                            db_AA.Auth.add_log(dev.id, 'proxy', u.username, userip, by="proxy", sessionid=None, timestamp=tz,message="proxy login")
                            # Mark this user as proxy-authenticated for upcoming accounting
                            self._proxy_users[(u.username, devip)] = tz
                            
                            if matched_hash_type == 'pth':
                                # Clear the Webfig proxy hash securely after use
                                try:
                                    from libs.db import db_pro
                                    UserpPro = db_pro.UserPoro
                                    user_pro = UserpPro.select().where(UserpPro.id == u.id).get()
                                    user_pro.thash = None
                                    user_pro.save()
                                except Exception as e:
                                    log.error("Failed to clear webfig proxy hash: %s", str(e))
                            
                    protocol.send_response(reply, addr)
                    return True
                
                db_AA.Auth.add_log(dev.id, 'failed', u.username, userip, by=None, sessionid=None, timestamp=tz, message="Wrong Password")
                self.send_auth_reject(protocol, pkt, addr)
        except Exception as e:
            log.error("Auth error: %s", str(e))
            self.send_auth_reject(protocol,pkt,addr)
            #log failed attempts

        

    def handle_acct_packet(self, protocol, pkt, addr):
        try:
            # for attr in pkt.keys():
            #     log.error("%s: %s" % (attr, pkt[attr]))
            ts = int(time.time())
            dev_ip=pkt['NAS-IP-Address'][0]
            dev=db_device.query_device_by_ip(dev_ip)
            type=pkt['Acct-Status-Type'][0]
            user=pkt['User-Name'][0]
            userip=pkt['Calling-Station-Id'][0]
            sessionid=pkt['Acct-Session-Id'][0]
            # Dedup: drop retransmitted accounting packets
            acct_key = ('acct', sessionid, type)
            if self._is_duplicate(acct_key):
                log.info("Dropping duplicate acct packet for %s (session %s, type %s)" % (user, sessionid, type))
                reply = self.CreateReplyPacket(pkt)
                protocol.send_response(reply, addr)
                return
            if type == 'Start':
                log.info("User %s logged in from %s" % (user, userip))
                # Check if this user authenticated via proxy
                proxy_key = (user, dev_ip)
                acct_by = None
                if proxy_key in self._proxy_users:
                    if ts - self._proxy_users[proxy_key] < 30:  # within 30s of proxy auth
                        acct_by = 'MW-proxy'
                    del self._proxy_users[proxy_key]
                    
                if acct_by == 'MW-proxy':
                    # Record the session ID so we can ignore the 'Stop' packet too
                    self._proxy_sessions[sessionid] = ts
                    # Cleanup old sessions
                    self._proxy_sessions = {k: v for k, v in self._proxy_sessions.items() if ts - v < 86400}
                else:
                    db_AA.Auth.add_log(dev.id, 'loggedin', user , userip , acct_by,timestamp=ts,sessionid=sessionid)
            elif type == 'Stop':
                log.info("User %s logged out from %s" % (user, userip))
                
                is_proxy_session = False
                if sessionid in self._proxy_sessions:
                    is_proxy_session = True
                    del self._proxy_sessions[sessionid]
                    
                if not is_proxy_session:
                    db_AA.Auth.add_log(dev.id, 'loggedout', user , userip , None,timestamp=ts,sessionid=sessionid)
        except Exception as e:
            log.error("Error in accounting: ")
            log.error(e)
            log.error("Received an accounting request")
            log.error("Attributes: ")
            log.error(pkt.keys())
        # for attr in pkt.keys():
        #     log.error("%s: %s" % (attr, pkt[attr]))
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



def main():
    loop = None
    server = None
    
    try:
        # create server and read dictionary
        loop = asyncio.get_event_loop()
        server = RadServer(loop=loop, dictionary=Dictionary('py/libs/raddic/dictionary'))
        secret = db_sysconfig.get_sysconfig('rad_secret')
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

