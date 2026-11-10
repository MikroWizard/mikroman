#!/usr/bin/python
# -*- coding: utf-8 -*-

# login_throttle.py: failed panel login throttling (/api/login, including wrong OTP)
# MikroWizard.com , Mikrotik router management solution
#
#   - per (client IP, username): `user_limit` failures within `window` seconds
#   - per client IP (any usernames): `ip_limit` failures within `window` seconds
#   - over a limit -> the login is refused for the rest of the window without checking the
#     password; a successful login clears the (IP, username) counter
#   - keyed by IP + username, so an attacker elsewhere cannot lock the real admin out
#   - Redis (the session store); if Redis fails, login works exactly as before (fail-open)
#   - admins can list and unlock (api/user/login_locks, api/user/unlock_login, or the
#     py/unlock_logins.py command line inside the container); an unlock also releases
#     RADIUS blocks of the same user / IP (signalled through Redis, see radius mule)

import hashlib
import logging
import time

log = logging.getLogger("login_throttle")

USER_LIMIT = 10
IP_LIMIT = 50
WINDOW = 900          # 15 minutes


PREFIX_USER = "mw:loginfail:u:"
PREFIX_IP = "mw:loginfail:ip:"
PREFIX_NAME = "mw:loginfail:n:"          # user hash -> username, for listing locks
RADIUS_UNLOCK = "mw:radius_unlock:"       # u:<user> / s:<ip> / all -> unlock time
RADIUS_UNLOCK_TTL = 86400


def _uhash(username):
    return hashlib.sha256(_norm(username).encode()).hexdigest()[:24]


def _norm(username):
    return str(username or "").strip().lower()


def _keys(ip, username):
    ip = str(ip or "")
    return "{}{}:{}".format(PREFIX_USER, ip, _uhash(username)), "{}{}".format(PREFIX_IP, ip)


def blocked_for(r, ip, username, user_limit=USER_LIMIT, ip_limit=IP_LIMIT):
    """Seconds the login stays refused (0 = allowed). Never raises."""
    if r is None:
        return 0
    try:
        ku, ki = _keys(ip, username)
        vu, vi = r.mget(ku, ki)
        for k, v in ((ku, vu), (ki, vi)):
            if v is not None and int(r.ttl(k) or 0) == -1:   # counter without expiry: repair
                r.expire(k, WINDOW)
        if (vu and int(vu) >= user_limit):
            return max(int(r.ttl(ku) or 0), 1)
        if (vi and int(vi) >= ip_limit):
            return max(int(r.ttl(ki) or 0), 1)
        return 0
    except Exception as e:
        log.warning("login throttle check skipped: %s", e)
        return 0


def failure(r, ip, username, window=WINDOW):
    """Count a failed login. The window starts at the first failure. Never raises."""
    if r is None:
        return
    try:
        keys = _keys(ip, username)
        p = r.pipeline()
        for k in keys:
            p.incr(k)
        counts = p.execute()
        for k, n in zip(keys, counts):
            if int(n) == 1:
                r.expire(k, window)
        r.set(PREFIX_NAME + _uhash(username), _norm(username), ex=window)
    except Exception as e:
        log.warning("login throttle update skipped: %s", e)


def success(r, ip, username):
    """Clear the (IP, username) counter after a successful login. Never raises."""
    if r is None:
        return
    try:
        r.delete(_keys(ip, username)[0])
    except Exception:
        pass


def _s(v):
    return v.decode() if isinstance(v, bytes) else v


def list_locks(r, user_limit=USER_LIMIT, ip_limit=IP_LIMIT):
    """Current panel lockouts: [{"type": "user"|"ip", "username", "ip", "failures",
    "seconds_left"}]. RADIUS blocks live in the RADIUS process and are not listed."""
    out = []
    if r is None:
        return out
    try:
        for key in r.scan_iter(match=PREFIX_USER + "*", count=500):
            key = _s(key)
            n = int(_s(r.get(key)) or 0)
            if n < user_limit:
                continue
            ip, uh = key[len(PREFIX_USER):].rsplit(":", 1)
            out.append({"type": "user", "username": _s(r.get(PREFIX_NAME + uh)) or "",
                        "ip": ip, "failures": n, "seconds_left": max(int(r.ttl(key) or 0), 0)})
        for key in r.scan_iter(match=PREFIX_IP + "*", count=500):
            key = _s(key)
            n = int(_s(r.get(key)) or 0)
            if n < ip_limit:
                continue
            out.append({"type": "ip", "username": "", "ip": key[len(PREFIX_IP):],
                        "failures": n, "seconds_left": max(int(r.ttl(key) or 0), 0)})
    except Exception as e:
        log.warning("login lock listing failed: %s", e)
    return out


def unlock(r, username=None, ip=None, everything=False):
    """Clear panel lockouts for a username (all IPs), an IP (all users), or everything, and
    release RADIUS blocks of the same user / IP. Returns the number of panel keys removed."""
    if r is None:
        return 0
    removed = 0
    now = "%.3f" % time.time()
    patterns = []
    if everything:
        patterns = [PREFIX_USER + "*", PREFIX_IP + "*", PREFIX_NAME + "*"]
        r.set(RADIUS_UNLOCK + "all", now, ex=RADIUS_UNLOCK_TTL)
    else:
        if username:
            patterns.append(PREFIX_USER + "*:" + _uhash(username))
            r.set(RADIUS_UNLOCK + "u:" + _norm(username), now, ex=RADIUS_UNLOCK_TTL)
        if ip:
            ip = str(ip).strip()
            patterns += [PREFIX_USER + ip + ":*", PREFIX_IP + ip]
            r.set(RADIUS_UNLOCK + "s:" + ip, now, ex=RADIUS_UNLOCK_TTL)
    for pat in patterns:
        for key in r.scan_iter(match=pat, count=500):
            removed += int(r.delete(key) or 0)
    return removed


def radius_unlocked_since(r, source, username):
    """Latest admin unlock time (unix) that applies to this RADIUS source / user, or 0."""
    try:
        vals = r.mget(RADIUS_UNLOCK + "all", RADIUS_UNLOCK + "u:" + _norm(username),
                      RADIUS_UNLOCK + "s:" + str(source))
        return max([float(_s(v)) for v in vals if v] or [0])
    except Exception:
        return 0
