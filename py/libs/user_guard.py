#!/usr/bin/python
# -*- coding: utf-8 -*-

# user_guard.py: limits for user management (no privilege escalation)
# MikroWizard.com , Mikrotik router management solution
#
# Before: any admin with users:write could give any user (including themselves) any role,
# including superuser, and any permission. Now, for actors that are not privileged:
#   - no role above their own level, never "superuser"
#   - no editing / deleting a user whose role is above their own (e.g. a superuser)
#   - their own role and permissions stay unchanged when they edit themselves (other fields
#     such as name, email, password are saved as usual; no error, so profile forms keep working)
#   - permissions they grant are capped at their own level per permission
# Privileged actors (superuser, and the guarded default admin which is always fully
# authorized by webutil) keep working exactly as before. Pure module, unit tested.

import json

LEVELS = {"disabled": 0, "customer_inactive": 0, "customer": 0, "readonly": 1, "editor": 2,
          "user": 3, "admin": 4, "superuser": 5}
PERM_LEVELS = {"none": 0, "None": 0, "read": 1, "write": 2, "full": 3}
PERM_NAMES = {0: "none", 1: "read", 2: "write", 3: "full"}


def role_level(role):
    return LEVELS.get(str(role or ""), 0)


def is_privileged(actor, guarded_id):
    return bool(actor) and (actor.role == "superuser" or str(actor.id) == str(guarded_id))


def _perms_of(user):
    try:
        p = json.loads(user.adminperms) if user.adminperms else {}
        return p if isinstance(p, dict) else {}
    except Exception:
        return {}


def check_assign_role(actor, new_role, guarded_id):
    """Error text when actor may not give new_role, else None."""
    if not new_role or is_privileged(actor, guarded_id):
        return None
    if new_role == "superuser" or role_level(new_role) > role_level(actor.role):
        return "You cannot assign a role above your own"
    return None


def check_target(actor, target, guarded_id):
    """Error text when actor may not edit / delete target, else None."""
    if is_privileged(actor, guarded_id) or target is None:
        return None
    if role_level(target.role) > role_level(actor.role):
        return "You cannot change a user with a higher role than yours"
    return None


def keeps_own_role(actor, target, guarded_id):
    """True when a non-privileged actor edits themselves: role / permissions stay as they are."""
    return (not is_privileged(actor, guarded_id) and actor is not None and target is not None
            and str(actor.id) == str(target.id))


def cap_perms(actor, requested, guarded_id):
    """requested permissions capped at the actor's own level per key.
    Returns (perms, capped_keys). Privileged actors and non-dict input are unchanged."""
    if is_privileged(actor, guarded_id) or not isinstance(requested, dict):
        return requested, []
    own = _perms_of(actor)
    out, capped = {}, []
    for key, value in requested.items():
        want = PERM_LEVELS.get(str(value), 0)
        have = PERM_LEVELS.get(str(own.get(key, "none")), 0)
        if want > have:
            out[key] = PERM_NAMES[have]
            capped.append(key)
        else:
            out[key] = value
    return out, capped
