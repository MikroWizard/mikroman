#!/usr/bin/python
# -*- coding: utf-8 -*-

# radius_ma.py: RADIUS Message-Authenticator handling (RFC 3579, BlastRADIUS / CVE-2024-3596)
# MikroWizard.com , Mikrotik router management solution
#
# Backward compatible by design:
#   - every reply to an Access-Request carries a valid Message-Authenticator as its first
#     attribute. Routers with require-message-auth enabled need it; routers with it disabled
#     (and RouterOS without the option) validate it when present, so a correct one is accepted
#     everywhere.
#   - requests: default mode "verify" only checks a Message-Authenticator that is present;
#     requests without one are handled exactly as before. "auto" (opt-in) additionally
#     requires it from a NAS-IP that has already sent a valid one (RouterOS 7.15+ always
#     does), so a spoofed NAS-IP without the shared secret is refused. "yes" (opt-in)
#     requires it always, "off" disables the inbound check (= 2.1.1 behaviour).
# Pure module (pyrad only), so it can be unit tested without the database.

import logging
import threading
import time

from pyrad.packet import AccessRequest

log = logging.getLogger("Radius")

MODE_VERIFY = "verify"     # default: check MA when present, accept requests without MA
MODE_REQUIRE = "yes"       # opt-in: drop Access-Requests without a valid MA
MODE_OFF = "off"           # no inbound check (2.1.1 behaviour)
MODE_AUTO = "auto"         # opt-in: require MA from a NAS that has sent a valid one before

AUTO_TTL = 7 * 86400       # a NAS is remembered this long after its last valid MA

ACCEPT = "accept"
DROP_INVALID = "drop-invalid"
DROP_MISSING = "drop-missing"


def parse_mode(value):
    """sysconfig radius_require_message_auth -> one of the MODE_* constants.
    Unknown or empty values mean the compatible default (verify)."""
    v = str(value or "").strip().lower()
    if v in ("yes", "true", "1", "require", "required"):
        return MODE_REQUIRE
    if v in ("off", "no", "false", "0", "disabled"):
        return MODE_OFF
    if v == "auto":
        return MODE_AUTO
    return MODE_VERIFY


def create_access_reply(pkt, **attributes):
    """Reply packet for pkt. Replies to an Access-Request get Message-Authenticator as the
    FIRST attribute, then the given attributes. pyrad computes the HMAC when the reply is
    serialised (ReplyPacket), with the final code, so setting reply.code = AccessReject
    afterwards stays valid. Other packet types (accounting, CoA) are unchanged."""
    reply = pkt.CreateReply()
    if pkt.code == AccessRequest:
        reply.add_message_authenticator()
    for key, value in attributes.items():
        reply.AddAttribute(key.replace('_', '-'), value)
    return reply


class NasTracker:
    """NAS-IPs that sent a valid Message-Authenticator (for MODE_AUTO). In-memory."""

    def __init__(self, ttl=AUTO_TTL):
        self.ttl = ttl
        self._seen = {}
        self._lock = threading.Lock()

    def learn(self, nas):
        if nas:
            with self._lock:
                self._seen[nas] = time.time()

    def requires(self, nas):
        if not nas:
            return False
        with self._lock:
            ts = self._seen.get(nas)
            if ts is None:
                return False
            if time.time() - ts > self.ttl:
                del self._seen[nas]
                return False
            return True


def _nas_of(pkt):
    try:
        return str(pkt['NAS-IP-Address'][0])
    except Exception:
        return None


def check_request(pkt, mode=MODE_VERIFY, tracker=None):
    """Inbound check of an Access-Request. Returns ACCEPT, DROP_INVALID or DROP_MISSING.

    A present Message-Authenticator that does not verify means a wrong shared secret or a
    modified packet; such a request already fails today (the router rejects our reply), so
    dropping it is safe (RFC 3579 3.2: silently discard). If pyrad cannot evaluate the
    attribute at all (unexpected error), the request is accepted in the default mode, so a
    library problem can never block logins that work today."""
    if mode == MODE_OFF:
        return ACCEPT
    if getattr(pkt, "message_authenticator", None):
        try:
            if pkt.verify_message_authenticator():
                if mode == MODE_AUTO and tracker is not None:
                    tracker.learn(_nas_of(pkt))
                return ACCEPT
            return DROP_INVALID
        except Exception as e:
            log.warning("Cannot verify Message-Authenticator: %s", e)
            return DROP_INVALID if mode == MODE_REQUIRE else ACCEPT
    if mode == MODE_REQUIRE:
        return DROP_MISSING
    if mode == MODE_AUTO and tracker is not None and tracker.requires(_nas_of(pkt)):
        return DROP_MISSING
    return ACCEPT
