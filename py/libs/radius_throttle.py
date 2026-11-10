#!/usr/bin/python
# -*- coding: utf-8 -*-

# radius_throttle.py: failed-login throttling for the embedded RADIUS server
# MikroWizard.com , Mikrotik router management solution
#
# Stops online password guessing against MikroWizard accounts over UDP 1812 without
# changing successful logins:
#   - keyed by the real UDP source address (a spoofed source cannot read the replies, so
#     guessing needs the attacker's own address) and the User-Name
#   - more than `limit` failures for (source, user) within `window` seconds -> that pair
#     gets an immediate Reject for `block` seconds, without checking the password
#   - more than `source_limit` failures from one source (any users) -> same for the source
#   - a successful login clears the (source, user) counter
#   - limit 0 disables the check. In-memory, one RADIUS mule; restart clears it.
#   - admins can unlock: release() drops blocks that started before an unlock time
#     (the unlock itself is signalled through Redis by libs/login_throttle.unlock)
# Thread safe: failures are recorded from pool threads, checks run on the event loop.

import threading
import time
from collections import deque

MAX_KEYS = 50000          # memory bound: oldest keys are dropped beyond this


class FailThrottle:

    def __init__(self, limit=10, window=300, block=300, source_limit=100):
        self.limit = int(limit or 0)
        self.window = int(window or 300)
        self.block = int(block or 300)
        self.source_limit = int(source_limit or 0)
        self._fails = {}          # key -> deque of timestamps
        self._blocked = {}        # key -> (blocked until, blocked since)
        self._was_blocked = set() # (source, user) keys whose block expired, until next success
        self._lock = threading.Lock()

    def _keys(self, source, user):
        return ("u", source, str(user or "").lower()), ("s", source)

    def blocked(self, source, user, now=None):
        """True when (source, user) or the source is blocked right now."""
        if not self.limit and not self.source_limit:
            return False
        now = time.time() if now is None else now
        ku, ks = self._keys(source, user)
        with self._lock:
            for k in (ku, ks):
                b = self._blocked.get(k)
                if b:
                    if b[0] > now:
                        return True
                    del self._blocked[k]
                    if k is ku and len(self._was_blocked) < MAX_KEYS:
                        self._was_blocked.add(ku)
        return False

    def is_active(self, kind, source, user=None, now=None):
        """True while the "user" (source, user) block or the "source" block is in force."""
        now = time.time() if now is None else now
        ku, ks = self._keys(source, user)
        with self._lock:
            b = self._blocked.get(ku if kind == "user" else ks)
            return bool(b) and b[0] > now

    def release(self, source, user, before):
        """Unblock (source, user) and the source when their block started at or before
        `before` (unix time of an admin unlock). Returns True when something was released."""
        ku, ks = self._keys(source, user)
        released = False
        with self._lock:
            for k in (ku, ks):
                b = self._blocked.get(k)
                if b and b[1] <= before:
                    del self._blocked[k]
                    self._fails.pop(k, None)
                    released = True
        return released

    def failure(self, source, user, now=None):
        """Record a failed login. Returns the blocks this failure started: a list with "user"
        and/or "source" (empty list = no new block, so it can be used as a boolean)."""
        if not self.limit and not self.source_limit:
            return []
        now = time.time() if now is None else now
        ku, ks = self._keys(source, user)
        started = []
        with self._lock:
            for k, limit in ((ku, self.limit), (ks, self.source_limit)):
                if not limit:
                    continue
                q = self._fails.get(k)
                if q is None:
                    if len(self._fails) >= MAX_KEYS:
                        self._fails.pop(next(iter(self._fails)))
                    q = self._fails[k] = deque()
                q.append(now)
                while q and q[0] < now - self.window:
                    q.popleft()
                if len(q) > limit and self._blocked.get(k, (0, 0))[0] <= now:
                    self._blocked[k] = (now + self.block, now)
                    q.clear()
                    started.append("user" if k is ku else "source")
        return started

    def success(self, source, user):
        """Clear the (source, user) counter after a successful login. Returns True when this
        pair had been blocked before (so a lockout event can be resolved)."""
        ku, _ = self._keys(source, user)
        with self._lock:
            self._fails.pop(ku, None)
            was_blocked = self._blocked.pop(ku, None) is not None
            if was_blocked:
                self._was_blocked.discard(ku)
                return True
            if ku in self._was_blocked:
                self._was_blocked.discard(ku)
                return True
        return False
