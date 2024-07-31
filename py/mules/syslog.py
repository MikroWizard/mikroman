#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process as a syslog server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from math import e
import socketserver
import re
import time

from libs.db import db_device
import logging
from libs.db import db_AA,db_events
log = logging.getLogger("SYSLOG")
from libs import util
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

import socketserver

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def extract_data_from_regex(self,regex,line):
        try:
            matches = re.finditer(regex, line, re.MULTILINE)
            sgroups=[]   
            for matchNum, match in enumerate(matches, start=1):
                for groupNum in range(0, len(match.groups())):
                    groupNum = groupNum + 1
                    sgroups.append(match.group(groupNum))
            return sgroups
        except:
            return None
    def handle(self):
        data = bytes.decode(self.request[0].strip(), encoding="utf-8")
        message = str(data)
        #get current timestamp
        ts = int(time.time())
        socket = self.request[1]
        dev=db_device.query_device_by_ip(self.client_address[0])
        regex=r'(.*),?(info.*|warning|critical) mikrowizard(\d+):.*'
        if dev:
            info=self.extract_data_from_regex(regex,message)
            opts=util.build_api_options(dev)
        try:
            int(info[2])
            if dev and dev.id != int(info[2]):
                log.error("Device id mismatch ignoring syslog for ip : {}".format(self.client_address[0]))
        except:
            log.error("**device id mismatch")
            log.error(message)
            log.error(self.client_address[0])
            log.error("device id mismatch**")
            dev=False
            pass
        if dev and dev.id == int(info[2]) and 'mikrowizard' in message and 'via api' not in message:
            if 'system,info,account' in message:
                regex = r"user (.*) logged (in|out) from (..*)via.(.*)"
                info=self.extract_data_from_regex(regex,message)
                users=util.get_local_users(opts)
                try:
                    if info[0] in users:
                        msg='local'
                    else:
                        msg='radius'
                    if 'logged in' in message:
                        if 'via api' not in message:
                            db_AA.Auth.add_log(dev.id, 'loggedin', info[0] , info[2] , info[3],timestamp=ts,message=msg)
                    elif 'logged out' in message:
                        if info[0] in users:
                            db_AA.Auth.add_log(dev.id, 'loggedout', info[0] , info[2] , info[3],timestamp=ts,message=msg)
                except Exception as e:
                    log.error(e)
                    log.error(message)
            elif 'system,error,critical' in message:
                if "login failure" in message:
                    users=util.get_local_users(opts)    
                    regex = r"login failure for user (.*) from (..*)via.(.*)"
                    info=self.extract_data_from_regex(regex,message)
                    ts = int(time.time())
                    if info[0] in users:
                        msg='local'
                    else:
                        msg='radius'
                    db_AA.Auth.add_log(dev.id, 'failed', info[0]  , info[1] , info[2],timestamp=ts,message=msg)
                elif "rebooted" in message:
                    regex=r'system,error,critical mikrowizard\d+: (.*)'
                    info=self.extract_data_from_regex(regex,message)
                    db_events.state_event(dev.id, "syslog", "Unexpected Reboot","Critical",1,info[0])
                    
            elif 'system,info mikrowizard' in message:
                regex= r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (winbox-\d.{1,3}\d\/.*\(winbox\)|mac-msg\(winbox\)|tcp-msg\(winbox\)|ssh|telnet|api|api-ssl|.*\/web|ftp|www-ssl).*:(.*)@(.*) \((.*)\)"
                if re.match(regex, message):
                    info=self.extract_data_from_regex(regex, message)
                    address=info[4].split('/')
                    ctype=''
                    if 'winbox' in info[2]:
                        ctype='winbox'
                        if 'tcp' in info[2]:
                            ctype='winbox-tcp'
                        elif 'mac' in info[2]:
                            ctype='winbox-mac'
                        if 'terminal' in address:
                            ctype+='/terminal'
                    elif 'ssh' in info[2]:
                        ctype='ssh'
                    elif 'telnet' in info[2]:
                        ctype='telnet'
                    elif '/web' in info[2]:
                        ctype=info[2].split('/')[1] + " " + "({})".format(info[2].split('/')[0])
                    elif 'api' in info[2]:
                        ctype='api'
                    db_AA.Account.add_log(dev.id,  info[0], info[1], info[3],message,ctype, address[0], info[5])
                elif "rebooted" in message:
                    db_events.state_event(dev.id, "syslog", "Router Rebooted","info",1,info[0])
                elif "resetting system configuration":
                    db_events.state_event(dev.id, "syslog", "Router reset","info",1,info[0])
                else:
                    regex = r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (.*)"
                    info=self.extract_data_from_regex(regex,message)
                    db_AA.Account.add_log(dev.id, info[0], info[1], info[2],message)
            elif 'interface,info mikrowizard' in message:
                link_regex = r"interface,info mikrowizard\d+: (.*) link (down|up).*"
                events=list(db_events.get_events_by_src_and_status("syslog", 0,dev.id).dicts())
                if "link down" in message:
                    info=self.extract_data_from_regex(link_regex,message)
                    db_events.state_event(dev.id, "syslog", "Link Down: " + info[0],"Warning",0,"Link is down for {}".format(info[0]))
                elif "link up" in message:
                    info=self.extract_data_from_regex(link_regex,message)
                    util.check_or_fix_event(events,'state',"Link Down: " + info[0])
            elif "dhcp,info mikrowizard" in message:
                dhcp_regex=r'dhcp,info mikrowizard\d+: (dhcp-client|.*) (deassigned|assigned|.*) (\d+\.\d+\.\d+\.\d+|on.*address)\s*(from|to|$)\s*(.*)'
                info=self.extract_data_from_regex(dhcp_regex,message)
                if info and "assigned" in message:
                    db_events.state_event(dev.id, "syslog", "dhcp assigned","info",1,"server {} assigned {} to {}".format(info[0],info[2],info[4]))
                elif info and "deassigned" in message:
                    db_events.state_event(dev.id, "syslog", "dhcp deassigned","info",1,"server {} deassigned {} from {}".format(info[0],info[2],info[4]))
                elif info and "dhcp-client" in message:
                    db_events.state_event(dev.id, "syslog", "dhcp client","info",1,"{} {}".format(info[1],info[2]))
            elif "wireless,info mikrowizard" in message:
                if ISPRO:
                    utilpro.wireless_syslog_event(dev ,message)
                else:
                    regex=r'wireless,info mikrowizard\d+: ([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})@(.*): (connected|disconnected), (signal strength|.*)? (-?\d{2})?.*'
                    info=self.extract_data_from_regex(regex,message)
                    if info:
                        strength=""
                        if len(info)>4:
                            strength=info[4]
                        db_events.state_event(dev.id, "syslog", "wireless client", "info", 1, "{} {} {} {} {}".format(info[0], info[1], info[2], info[3],strength))
                        log.error(len(info))
                        log.error(message)
            else:
                log.error(message)
if __name__ == "__main__":
    try:
        server = socketserver.UDPServer(("0.0.0.0",5014), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
