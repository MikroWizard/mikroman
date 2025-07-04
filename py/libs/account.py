#!/usr/bin/python
# -*- coding: utf-8 -*-

# account.py: user account related operations, passwords
# MikroWizard.com , Mikrotik router management solution
# Author: Tomi.Mickelsson@iki.fi modified by sepehr.ha@gmail.com

import re
from flask import session
from passlib.context import CryptContext
import json
import logging
import string
import secrets
import random
import smtplib
from email.message import EmailMessage
from config import SMTP_EMAIL, SMTP_PASSWORD, SMTP_SERVER, SMTP_PORT

log = logging.getLogger("account")


pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"],
    deprecated="auto" # list of supported algos
)


def build_session(user_obj, is_permanent=True):
    """On login+signup, builds the server-side session dict with the data we
    need. userid being the most important."""

    assert user_obj
    assert user_obj.id
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

def generate_random_password(length=12):
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits

    # Ensure at least one of each required character type
    all_chars = uppercase + lowercase + digits
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits)
    ]

    # Fill the rest with random choices from all sets
    password += random.choices(all_chars, k=length - 3)

    # Shuffle the list to randomize character positions
    random.shuffle(password)

    return ''.join(password)


def send_password_email(to_email: str, user_name: str, password: str) -> bool:

    subject = "Your Account Password"
    body = f"""
    Hello {user_name},

    Your account password is: {password}

    Please keep it safe and secure.

    Regards,
    CircleProtect Team
    """

    # smtp_email = os.getenv("SMTP_MAIL_SENDER")
    # smtp_app_pass = os.getenv("SMTP_APP_PASSWORD")

    print("smtp_email",SMTP_EMAIL, SMTP_PASSWORD, SMTP_SERVER, SMTP_PORT)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            smtp.send_message(msg)
            return True
    except Exception as e:
            print("Email sending failed:", e)
            return False