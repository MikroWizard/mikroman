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
import json
from collections import defaultdict
import config as app_config
import threading
from libs import traffic_math

import logging
log = logging.getLogger("RedisDB")


# --------------------------------------------------------------------------
# Shared connection pool: one pool per process instead of one per RedisDB() instance
# (the poller creates several RedisDB objects per device per cycle).
_POOLS = {}
_POOLS_LOCK = threading.Lock()


def _get_pool(host, port, password):
    key = (host, port, password)
    pool = _POOLS.get(key)
    if pool is None:
        with _POOLS_LOCK:
            pool = _POOLS.get(key)
            if pool is None:
                pool = redis.ConnectionPool(host=host, port=port, password=password, db=0)
                _POOLS[key] = pool
    return pool


def align_timeseries_grid(raw_points, start_ms, end_ms, step_ms, fill_value=0.0, open_bucket=True):
    """Regular time grid for chart series (see libs.traffic_math.align_timeseries_grid)."""
    return traffic_math.align_timeseries_grid(raw_points, start_ms, end_ms, step_ms,
                                              fill_value=fill_value, open_bucket=open_bucket)


def chart_series(raw_points, sensor, delta, start_ms, end_ms):
    """Shape raw TimeSeries points for charts.

    Traffic rate sensors (rx-/tx-/rxp-/txp-*) are placed on a regular grid so downtime shows
    as 0 instead of a jump. Other sensors (cpu, memory, health, radio signal...) are returned
    unchanged - a 0 there would be a false reading.
    """
    step = traffic_math.DELTA_STEP_MS.get(delta, 60000)
    if not traffic_math.is_rate_sensor(sensor):
        points = [(p[0], p[1]) for p in raw_points if p and len(p) >= 2]
        return points[-30:] if delta == 'live' else points
    if delta == 'live':
        live_start = max(int(start_ms), (int(end_ms) // step - 30) * step)
        return align_timeseries_grid(raw_points, live_start, end_ms, step)[-30:]
    return align_timeseries_grid(raw_points, start_ms, end_ms, step)


class RedisDB(object):
    def __init__(self, options):
        self.dev_id = options.get('dev_id',False)
        self.keys= options.get('keys',[])
        self.current_time = datetime.datetime.now()
        self.start_time = options.get('start_time',self.current_time + datetime.timedelta(days=-30))
        self.end_time =  options.get('end_time',self.current_time)
        self.retention = options.get('retention', 2629800000)
        _redis_host = getattr(app_config, 'redishost', '127.0.0.1:6379')
        _redis_pass = app_config.srvconf.get('PYSRV_REDIS_PASSWORD', None) or None
        _redis_parts = _redis_host.split(':')
        self.r = redis.Redis(connection_pool=_get_pool(
            _redis_parts[0],
            int(_redis_parts[1]) if len(_redis_parts) > 1 else 6379,
            _redis_pass,
        ))
        self.delta = options.get('delta','')

    def create_sensor_rts(self,sensor):
        retention=self.retention
        if "rx" in sensor or "tx" in sensor:
            retention=21600000
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
            self.r.ts().create(ruledaily_key,retention_msecs=3600000*2160,duplicate_policy="last")
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



    def get_cached_counters(self, dev_id):
        try:
            val = self.r.get(f"iface_counters::{dev_id}")
            if val:
                return json.loads(val.decode('utf-8') if isinstance(val, bytes) else val)
        except Exception as e:
            log.warning(f"Failed to get cached counters for dev {dev_id}: {e}")
        return {}

    def set_cached_counters(self, dev_id, counters, ttl=1800):
        try:
            self.r.setex(f"iface_counters::{dev_id}", ttl, json.dumps(counters))
        except Exception as e:
            log.warning(f"Failed to set cached counters for dev {dev_id}: {e}")

    def add_dev_data(self,info=[]):
        if self.dev_id==False or not info:
            return
        datalist=[]
        for key, val in info.items():
            try:
                numeric_val = float(val) if val is not None else 0.0
            except (ValueError, TypeError):
                numeric_val = 0.0
            master_key="sensor::{}::{}".format(self.dev_id,key)
            datalist.append((master_key , '*' , numeric_val))
            
        try:
            results = self.r.ts().madd(datalist)
            if any(isinstance(x, Exception) for x in results):
                for k in info.keys():
                    try:
                        self.create_sensor_rts(k)
                    except Exception:
                        pass
                try:
                    self.r.ts().madd(datalist)
                except Exception as e2:
                    log.error(f"Error executing madd retry for dev {self.dev_id}: {e2}")
        except redis.exceptions.ResponseError as e:
            if "TSDB: the key does not exist" in str(e) or "not a TSDB key" in str(e):
                for k in info.keys():
                    try:
                        self.create_sensor_rts(k)
                    except Exception:
                        pass
                try:
                    self.r.ts().madd(datalist)
                except Exception as e2:
                    log.error(f"Error executing madd retry for dev {self.dev_id}: {e2}")
            else:
                log.error(f"Redis ResponseError adding dev data for dev {self.dev_id}: {e}")
        except Exception as e:
            log.error(f"Redis error adding dev data for dev {self.dev_id}: {e}")
        return True

    def get_dev_data(self,sensor):
        if self.dev_id==False:
            return []
        start=int(time.mktime(self.start_time.timetuple())* 1000)
        end=int(time.mktime(self.end_time.timetuple())* 1000)
        if self.delta=='live':
            master_key="sensor::{}::{}".format(self.dev_id,sensor)
        else:
            master_key="sensor{}::{}::{}".format(self.delta,self.dev_id,sensor)

        try:
            if self.delta=='live':
                raw = list(reversed(self.r.ts().revrange(master_key,start,end,count=30)))
            else:
                raw = self.r.ts().range(master_key,start,end)
        except Exception:
            return []
        return chart_series(raw, sensor, self.delta, start, end)
    
    def get_dev_last_data(self,sensor):
        if self.dev_id==False:
            return None
        master_key="sensor::{}::{}".format(self.dev_id,sensor)
        try:
            return self.r.ts().get(master_key)
        except Exception:
            return None

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
            if isinstance(res_list, Exception) or not res_list:
                continue
            if delta == 'live':
                res_list = list(reversed(res_list))
            # Align every device on the same grid BEFORE summing, so one device's poll
            # jitter does not show up as a dip in the group total.
            for ts, val in chart_series(res_list, key, delta, start_ms, end_ms):
                summed_data[key][ts] += val

        out = {}
        for key in keys:
            raw_pairs = [(ts, summed_data[key][ts]) for ts in sorted(summed_data[key].keys())]
            out[key] = chart_series(raw_pairs, key, delta, start_ms, end_ms)
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