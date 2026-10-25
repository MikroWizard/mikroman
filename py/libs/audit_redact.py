#!/usr/bin/python
# -*- coding: utf-8 -*-

# audit_redact.py: mask secret values before they are written to the System Log (syslogs.data)
# MikroWizard.com , Mikrotik router management solution
#
# Security-only and fail-open:
#   - only VALUES of known secret keys change ("***"); keys, structure and other values stay
#   - when nothing is masked the original object is returned (stored byte-identical)
#   - plain text / non-JSON data is never touched
#   - any error returns the original data (behaves exactly like before this module existed)
# Pure module (no DB / Redis imports) so db_syslog can import it without side effects.
# Kill switch: environment MW_AUDIT_REDACT=0 disables masking.

import json
import logging
import os
import re

log = logging.getLogger("audit_redact")

_REDACT_ENABLED = os.getenv("MW_AUDIT_REDACT", "1") != "0"
MASK = "***"
_MAX_DEPTH = 20

# exact key names, compared lowercase with '-' normalised to '_'
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "oldpass", "newpass", "new_password", "old_password",
    "enable_password", "secret", "rad_secret", "token", "bot_token", "api_key",
    "apikey", "ai_api_key", "private_key", "ssh_key", "otp", "otp_secret",
    "community", "auth_key", "priv_key", "smtp_password", "webhook_url",
})
_SENSITIVE_SUFFIXES = ("_password", "_secret", "_token", "_private_key")

# cheap pre-filter: only parse JSON when a sensitive-looking key name is present
_QUICK = re.compile(r'"[^"]*(pass|secret|token|key|otp|community|webhook)[^"]*"\s*:', re.I)

# same idea for SQL (PostgreSQL ~*), used by the backfill to find candidate rows
SQL_CANDIDATE_REGEX = r'"[^"]*(pass|secret|token|key|otp|community|webhook)[^"]*"[[:space:]]*:'


def _is_sensitive(key):
    k = str(key).lower().replace("-", "_")
    return k in _SENSITIVE_KEYS or k.endswith(_SENSITIVE_SUFFIXES)


def _maskable(v):
    return v not in (None, "", MASK) and not isinstance(v, (dict, list, bool))


def _mask(obj, depth=0):
    """Mask in place. Returns True when anything changed."""
    if depth > _MAX_DEPTH:
        return False
    changed = False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _is_sensitive(k):
                if isinstance(v, dict):
                    # settings shape: {"rad_secret": {"value": "...", "modified": ...}}
                    if "value" in v and _maskable(v["value"]):
                        v["value"] = MASK
                        changed = True
                    else:
                        changed |= _mask(v, depth + 1)
                elif isinstance(v, list):
                    changed |= _mask(v, depth + 1)
                elif _maskable(v):
                    obj[k] = MASK
                    changed = True
            elif isinstance(v, (dict, list)):
                changed |= _mask(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                changed |= _mask(v, depth + 1)
    return changed


def redact_audit_data(data):
    """Return data with secret values masked. Never raises.
    Returns the very same object when nothing was masked or on any error."""
    try:
        if not _REDACT_ENABLED or not isinstance(data, str) or len(data) < 2:
            return data
        if data.lstrip()[:1] not in ("{", "[") or not _QUICK.search(data):
            return data
        parsed = json.loads(data)
        if not _mask(parsed):
            return data
        return json.dumps(parsed)
    except Exception:
        return data
