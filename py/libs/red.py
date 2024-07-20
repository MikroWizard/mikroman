#!/usr/bin/python
# -*- coding: utf-8 -*-

# red.py: read/write data in Redis
#   - get/set key values with expiration time
#   - simple list operations
#   - atomic increment, getset
#
#
# https://redis.io/commands
# https://github.com/andymccurdy/redis-py
#
# MikroWizard.com , Mikrotik router management solution
# Author: Tomi.Mickelsson@iki.fi modified by sepehr.ha@gmail.com

import redis
import datetime
import time
from collections import defaultdict


import logging
log = logging.getLogger("RedisDB")


# --------------------------------------------------------------------------
# key values
class RedisDB(object):
    def __init__(self, options):
        self.dev_id = options.get('dev_id',False)
        self.keys= options.get('keys',[])
        self.current_time = datetime.datetime.now()
        self.start_time = options.get('start_time',self.current_time + datetime.timedelta(days=-30))
        self.end_time =  options.get('end_time',self.current_time)
        self.retention = options.get('retention',2629800000)
        self.r = redis.Redis(host='localhost', port=6379, db=0)
        self.delta = options.get('delta','')


    def create_sensor_rts(self,sensor):
        retention=self.retention
        if "rx" in sensor or "tx" in sensor:
            retention=3600000
        if self.dev_id==False:
            return
        master_key="sensor::{}::{}".format(self.dev_id,sensor)
        rule5m_key="sensor5m::{}::{}".format(self.dev_id,sensor)
        rule1h_key="sensor1h::{}::{}".format(self.dev_id,sensor)
        ruledaily_key="sensordaily::{}::{}".format(self.dev_id,sensor)
        #Create master key for sensor data or change retention time
        try:
            self.r.ts().create(master_key,retention_msecs=retention,duplicate_policy="last")
        except Exception as e:
            self.r.ts().alter(master_key,retention_msecs=retention)
            pass
        #Create ryle keys for sensor avg data or change retention time
        try:
            #5m avg store for 24h
            #1h avg store for 2weeks
            #daily avg store for 3month
            self.r.ts().create(rule5m_key,retention_msecs=3600000*24,duplicate_policy="last")
            self.r.ts().create(rule1h_key,retention_msecs=3600000*336,duplicate_policy="last")
            self.r.ts().create(ruledaily_key,retention_msecs=retention*2160,duplicate_policy="last")
        except Exception as e:
            self.r.ts().alter(rule5m_key,retention_msecs=3600000*24)
            self.r.ts().alter(rule1h_key,retention_msecs=3600000*336)
            self.r.ts().alter(ruledaily_key,retention_msecs=3600000*2160)
            pass
        #Create rule for 5m avg data or change retention time
        try:
            self.r.ts().createrule(master_key, rule5m_key, "avg" ,bucket_size_msec=300000)
        except Exception as e:
            pass
        #Create rule for 1hour avg data or change retention time
        try:
            self.r.ts().createrule(master_key, rule1h_key, "avg" ,bucket_size_msec=3600000)
        except Exception as e:
            pass
        #Create rule for daily avg data or change retention time
        try:
            self.r.ts().createrule(master_key, ruledaily_key, "avg" ,bucket_size_msec=86400000)
        except Exception as e:
            pass
        return True

    def dev_create_keys(self):
        if self.dev_id==False:
            return
        for key in self.keys:
            try:
                self.create_sensor_rts(key)
            except Exception as e:
                log.error(e)
                pass
        return True


    def add_dev_data(self,info=[]):
        if self.dev_id==False:
            return
        datalist=[]
        for key, val in info.items():
            master_key="sensor::{}::{}".format(self.dev_id,key)
            datalist.append((master_key , '*' , val))
        self.r.ts().madd(datalist)
        return True

    def get_dev_data(self,sensor):
        if self.dev_id==False:
            return
        start=int(time.mktime(self.start_time.timetuple())* 1000)
        end=int(time.mktime(self.end_time.timetuple())* 1000)
        if self.delta=='live':
            master_key="sensor::{}::{}".format(self.dev_id,sensor)
        else:
            master_key="sensor{}::{}::{}".format(self.delta,self.dev_id,sensor)

        if self.delta=='live':
            return list(reversed(self.r.ts().revrange(master_key,start,end,count=30)))
        return self.r.ts().range(master_key,start,end)
    
    def get_dev_last_data(self,sensor):
        if self.dev_id==False:
            return
        master_key="sensor::{}::{}".format(self.dev_id,sensor)
        return self.r.ts().get(master_key)

    def get_dev_data_keys(self):
        if self.dev_id==False:
            return
        data = defaultdict(list)
        for key in self.keys:
            try:
                data[key]=self.get_dev_data(key)
            except Exception as e:
                log.error(e)
                pass
        return data

