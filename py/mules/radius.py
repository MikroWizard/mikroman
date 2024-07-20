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
import traceback
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

log = logging.getLogger("Radius")

logging.basicConfig(filename="pyrad.log", level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")

class RadServer(ServerAsync):

    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                              debug=True)
    def verifyMsChapV2(self,pkt,userpwd,group,nthash):

        ms_chap_response = pkt['MS-CHAP2-Response'][0]
        authenticator_challenge = pkt['MS-CHAP-Challenge'][0]
        
        if len(ms_chap_response)!=50:
            raise Exception("Invalid MSCHAPV2-Response attribute length")

        nt_response = ms_chap_response[26:50]
        peer_challenge = ms_chap_response[2:18]
        _user_name = pkt.get(1)[0]
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
            dev=db_device.query_device_by_ip(devip)
            if not dev:
                self.send_auth_reject(protocol,pkt,addr)
                return
            u = db.get_user_by_username(username)
            if not u:
                    self.send_auth_reject(protocol,pkt,addr)
                    db_AA.Auth.add_log(dev.id, 'failed',  username , userip , by=None,sessionid=None,timestamp=tz,message="User Not Exist")
                    return
            else:
                #get user permision related to device
                
                if not dev:
                    self.send_auth_reject(protocol, pkt, addr)
                    db_AA.Auth.add_log(dev.id, 'failed', username, userip, by=None, sessionid=None, timestamp=tz, message="Device Not Exist")
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
                            db_AA.Auth.add_log(dev.id, 'failed',  username , userip , by=None,sessionid=None,timestamp=tz,message="Unable to verify group")
                            return
                nthash=u.hash
                if force_perms:
                    reply=self.verifyMsChapV2(pkt,"password",perm[0].perm_id.name,nthash)
                else:
                    reply=self.verifyMsChapV2(pkt,"password",False,nthash)
                if reply:
                    protocol.send_response(reply, addr)
                    return
                db_AA.Auth.add_log(dev.id, 'failed',  username , userip , by=None,sessionid=None,timestamp=tz,message="Wrong Password")
                self.send_auth_reject(protocol,pkt,addr)
        except Exception as e:
            print(e)
            self.send_auth_reject(protocol,pkt,addr)
            #log failed attempts

        

    def handle_acct_packet(self, protocol, pkt, addr):
        try:
            ts = int(time.time())
            dev_ip=pkt['NAS-IP-Address'][0]
            dev=db_device.query_device_by_ip(dev_ip)
            type=pkt['Acct-Status-Type'][0]
            user=pkt['User-Name'][0]
            userip=pkt['Calling-Station-Id'][0]
            sessionid=pkt['Acct-Session-Id'][0]
            if type == 'Start':
                db_AA.Auth.add_log(dev.id, 'loggedin', user , userip , None,timestamp=ts,sessionid=sessionid)
            elif type == 'Stop':
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
    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = RadServer(loop=loop, dictionary=Dictionary('py/libs/raddic/dictionary'))
    secret = db_sysconfig.get_sysconfig('rad_secret')
    server.hosts["0.0.0.0"] = RemoteHost("0.0.0.0",
                                           secret.encode(),
                                           "localhost")

    try:

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
        except KeyboardInterrupt as k:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    except Exception as exc:
        log.error('Error: ', exc)
        log.error('\n'.join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    loop.close()

    
if __name__ == '__main__':
    main()

