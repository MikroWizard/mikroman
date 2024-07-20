#!/usr/bin/python
# -*- coding: utf-8 -*-

# account.py: user account related operations, passwords
# MikroWizard.com , Mikrotik router management solution
# Author: Tomi.Mickelsson@iki.fi modified by sepehr.ha@gmail.com

import re
from shutil import ExecError
from flask import session
from passlib.context import CryptContext
import json
import logging
log = logging.getLogger("account")


pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"] # list of supported algos
)


def build_session(user_obj, is_permanent=True):
    """On login+signup, builds the server-side session dict with the data we
    need. userid being the most important."""

    assert user_obj
    assert user_obj.id
    log.error(session)
    # make sure session is empty
    session.clear()
    session['userid'] = user_obj.id
    session['role'] = user_obj.role # if you update user.role, update this too
    try:
        session['perms'] = json.loads(user_obj.adminperms)
    except Exception as e:
        log.error(e)
        session['perms']=[]
    # remember session even over browser restarts?
    session.permanent = is_permanent

    # could also store ip + browser-agent to verify freshness
    # of the session: only allow most critical operations with a fresh
    # session


def hash_password(password):
    """Generate a secure hash out of the password. Salts automatically."""

    return pwd_context.hash(password)


def check_password(hash, password):
    """Check if given plaintext password matches with the hash."""

    return pwd_context.verify(password, hash)


def check_password_validity(passwd):
    """Validates the given plaintext password. Returns None for success,
       error text on error."""

    err = None

    if not passwd or len(passwd) < 6:
        err = "Password must be atleast 6 characters"

    elif not re.search(r"[a-z]", passwd) \
            or not re.search(r"[A-Z]", passwd) \
            or not re.search(r"[0-9]", passwd):
        err = "Password must contain a lowercase, an uppercase, a digit"

    if err:
        log.error("password validity: %s", err)

    return err


def new_signup_steps(user_obj):
    """Perform steps for a new signup."""
    #nothing for now
    return True