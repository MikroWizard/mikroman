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

    def get_summed_dev_data(self, device_ids, keys, delta, start_time, end_time):
        """
        Read time-series from multiple devices via pipeline, sum across them.
        Returns same dict-of-lists shape as get_dev_data_keys().
        """
        start_ms = int(time.mktime(start_time.timetuple()) * 1000)
        end_ms = int(time.mktime(end_time.timetuple()) * 1000)

        pipe = self.r.pipeline()
        commands = []
        for dev_id in device_ids:
            for key in keys:
                if delta == 'live':
                    mk = "sensor::{}::{}".format(dev_id, key)
                    pipe.ts().revrange(mk, start_ms, end_ms, count=30)
                else:
                    mk = "sensor{}::{}::{}".format(delta, dev_id, key)
                    pipe.ts().range(mk, start_ms, end_ms)
                commands.append((dev_id, key))

        try:
            results = pipe.execute(raise_on_error=False)
        except Exception as e:
            log.error("Redis pipeline failed: {}".format(e))
            return {key: [] for key in keys}

        summed_data = {key: defaultdict(float) for key in keys}

        for idx, (dev_id, key) in enumerate(commands):
            res_list = results[idx]
            if isinstance(res_list, Exception):
                continue
            for item in res_list:
                ts = item[0]
                val = item[1]
                if delta == 'live':
                    ts = (ts // 10000) * 10000
                summed_data[key][ts] += val

        out = {}
        for key in keys:
            sorted_ts = sorted(summed_data[key].keys())
            if delta == 'live':
                out[key] = [(ts, summed_data[key][ts]) for ts in sorted_ts[-30:]]
            else:
                out[key] = [(ts, summed_data[key][ts]) for ts in sorted_ts]
        return out


    def store_data(self, device_id, key, command):
        """
        store data for specific key of specific command
        """
        redis_key = f"device:{device_id}:{key}"
        
        # Add the command to the list
        self.r.rpush(redis_key, command.encode('utf-8'))
        
        # Trim the list to keep only the last 20 commands
        # self.r.ltrim(redis_key, -20, -1)

    def get_last_n_data(self, device_id, key, count=20):
        """
        Retrieves the last 'count' data executed for a specific device ID and key.
        """
        redis_key = f"device:{device_id}:{key}"
        raw_commands = self.r.lrange(redis_key, -count, -1)
        return [cmd.decode('utf-8') for cmd in raw_commands]
        # return self.r.lrange(redis_key, -count, -1)