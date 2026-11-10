#!/usr/bin/python
# -*- coding: utf-8 -*-

# unlock_logins.py: clear failed-login lockouts from the command line (panel + RADIUS)
# MikroWizard.com , Mikrotik router management solution
#
# For when every admin is locked out. Inside the container:
#   docker exec -w /app/py mikroman python3 unlock_logins.py --list
#   docker exec -w /app/py mikroman python3 unlock_logins.py --user admin
#   docker exec -w /app/py mikroman python3 unlock_logins.py --ip 192.168.1.107
#   docker exec -w /app/py mikroman python3 unlock_logins.py --all

import argparse
import os
import sys

os.environ.setdefault("PYSRV_CONFIG_PATH", "/conf/server-conf.json")

import config                         # noqa: E402  (needs PYSRV_CONFIG_PATH first)
from libs import login_throttle      # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Clear MikroWizard failed-login lockouts (panel and RADIUS).")
    ap.add_argument("--user", help="unlock this username (all IPs)")
    ap.add_argument("--ip", help="unlock this client / router IP (all users)")
    ap.add_argument("--all", action="store_true", help="unlock everything")
    ap.add_argument("--list", action="store_true", help="show current panel lockouts")
    a = ap.parse_args()
    r = config.flask_config["SESSION_REDIS"]
    if a.list:
        locks = login_throttle.list_locks(r)
        if not locks:
            print("No panel lockouts.")
        for l in locks:
            print("{type:4s} user={username!r} ip={ip} failures={failures} unlocks_in={seconds_left}s".format(**l))
        return 0
    if not (a.user or a.ip or a.all):
        ap.print_help()
        return 1
    n = login_throttle.unlock(r, username=a.user, ip=a.ip, everything=a.all)
    print("Unlocked ({} panel counter(s) removed; RADIUS blocks are released on the next login).".format(n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
