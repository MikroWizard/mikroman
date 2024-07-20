#!/usr/bin/python
# -*- coding: utf-8 -*-


# ssh_helper.py: ssh related operations
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import datetime
from libs.check_routeros.routeros_check.helper import logger, RouterOSVersion
import paramiko
import re


import logging
log = logging.getLogger("SSH_HELPER")


#rdb = redis.StrictRedis(host=config.redishost)
#rdb = redis.from_url('redis://{}'.format(config.redishost))
#r = redis.Redis()

# --------------------------------------------------------------------------
# key values
class SSH_Helper(object):
    def __init__(self, options):
        self.dev_id = options.get('dev_id',False)
        self.host = options.get('host',False)
        self.username = options.get('username',False)
        self.password = options.get('password',False)
        self.api_port = options.get('port',False)
        self.ssh_port = options.get('ssh_port',22)
        self.router = options.get('router',False)
        self.current_time = datetime.datetime.now()
        self.ssh=paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def get_config(self, retrieve='all', full=False, sanitized=False):
        if not self.router:
            return False
        configs = {'running': '', 'candidate': '', 'startup': ''}
        command = ["export", "terse"]
        version = tuple(self.router.api('/system/package/update/print'))[0]
        version = RouterOSVersion(version['installed-version'])
        if full:
            command.append("verbose")
        if version.major >= 7 and not sanitized:
            command.append("show-sensitive")
        if version.major <= 6 and sanitized:
            command.append("hide-sensitive")
        self.ssh.connect(
            self.host,
            port=self.ssh_port,
            username=self.username,
            password=self.password,
            look_for_keys=False,
            allow_agent=False
        )
        _x, stdouts, _y = self.ssh.exec_command(" ".join(command))
        config = stdouts.read().decode().strip()
        # remove date/time in 1st line
        config = re.sub(r"^# \S+ \S+ by (.+)$", r'# by \1', config, flags=re.MULTILINE)
        if retrieve in ("running", "all"):
            configs['running'] = config
        return configs['running']
    
    def exec_command(self, command):
        self.ssh.connect(
            self.host,
            port=self.ssh_port,
            username=self.username,
            password=self.password,
            look_for_keys=False,
            allow_agent=False
        )
        _x, stdouts, _y = self.ssh.exec_command(command)
        return stdouts.read().decode().strip()