#!/usr/bin/python
# -*- coding: utf-8 -*-

# device_state.py: online / offline state and live uptime of devices, kept by the poller
# MikroWizard.com , Mikrotik router management solution
#
# The devices table keeps `uptime` as the poller last wrote it (every 10 minutes, to save DB
# writes) and never clears it, so an unreachable router kept showing its old uptime. The
# poller records here, once per cycle and in one Redis write, which routers answered (with
# their uptime) and which did not. The devices list then shows a live uptime for online
# routers (uptime at the poll + time since) and "Offline" for the others.
#
#   hash KEY: dev_id -> "<seen_ts>|<uptime_seconds>"   answered the poll at seen_ts
#                       "<since_ts>|-1"                 unreachable since since_ts

import time

import config

KEY = "mw:dev:state"
OFFLINE_TEXT = "Offline"
# Seen within this many seconds = state is current; older (poller stopped, device removed from
# polling) = unknown. One poll interval + the longest poll cycle + a margin.
GRACE_SECONDS = 60 + int(getattr(config, "DATAGRABBER_CYCLE_DEADLINE", 240)) + 60


def record_cycle(r, online, offline, now=None):
    """Poller, once per cycle. online: {dev_id: uptime_seconds}, offline: [dev_id].
    A device that stays unreachable keeps the time it went offline."""
    now = int(now or time.time())
    mapping = {str(dev_id): "{}|{}".format(now, int(up or 0)) for dev_id, up in online.items()}
    offline = [str(d) for d in offline if str(d) not in mapping]
    if offline:
        for dev_id, cur in zip(offline, r.hmget(KEY, offline)):
            since = now
            if cur:
                ts, _, up = (cur.decode() if isinstance(cur, bytes) else cur).partition("|")
                if up == "-1" and ts.isdigit():
                    since = int(ts)          # already offline: keep the time it went down
            mapping[dev_id] = "{}|-1".format(since)
    if mapping:
        r.hset(KEY, mapping=mapping)


def get_states(r, dev_ids, now=None):
    """{dev_id: state} for the devices list, one Redis read for the whole page.
    state = {"online": True, "uptime_s": live uptime} | {"online": False, "since": ts}
          | None (no current poller information: not polled yet, or the poller stopped)."""
    ids = [str(d) for d in dev_ids]
    if not ids:
        return {}
    now = int(now or time.time())
    out = {}
    for dev_id, raw in zip(ids, r.hmget(KEY, ids)):
        state = None
        if raw:
            ts, _, up = (raw.decode() if isinstance(raw, bytes) else raw).partition("|")
            try:
                ts, up = int(ts), int(up)
            except ValueError:
                ts, up = 0, 0
            if up < 0:
                state = {"online": False, "since": ts}
            elif now - ts <= GRACE_SECONDS:
                state = {"online": True, "uptime_s": up + max(0, now - ts)}
        out[dev_id] = state
    return out


def format_uptime(seconds):
    """RouterOS style, as stored in devices.uptime: 1w2d3h4m5s."""
    seconds = int(seconds)
    w, seconds = divmod(seconds, 7 * 86400)
    d, seconds = divmod(seconds, 86400)
    h, seconds = divmod(seconds, 3600)
    m, s = divmod(seconds, 60)
    parts = [(w, "w"), (d, "d"), (h, "h"), (m, "m"), (s, "s")]
    text = "".join("{}{}".format(v, u) for v, u in parts if v)
    return text or "0s"
