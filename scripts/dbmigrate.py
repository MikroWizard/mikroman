#!/usr/bin/python
# -*- coding: utf-8 -*-

# dbmigrate.py: migrate the local database
#   - run either on dev machine or at server
#
# Author: Tomi.Mickelsson@iki.fi & Edited by sepehr.ha@gmail.com

import os
import config
from urllib.parse import quote


if config.DATABASE_HOST.startswith("/"):
    # sqlite
    # note: can't use full path here!
    # db will appear in "/app/data/mydb.sqlite" (mapped volume locally)
    cmd = "pw_migrate migrate --directory=/app/migrations_sqlite --database=sqlite:/data/mydb.sqlite"
else:
    # postgresql
    cmd = "pw_migrate migrate --database='postgresql://{}:{}/{}?user={}&password={}'".format(
        config.DATABASE_HOST,
        config.DATABASE_PORT,
        config.DATABASE_NAME,
        config.DATABASE_USER,
        quote(config.DATABASE_PASSWORD))

# print(cmd)

ret = os.system(cmd)
if ret:
    print("migrate ERROR", ret)
else:
    print("migrate OK")

# Install updated requirements before any restart — this ensures
# packages (e.g. netmiko) are available when the server comes back up,
# even when dbmigrate.py kills uWSGI via the transition patch below.
print("Installing requirements from /app/reqs.txt...")
os.system("python3 -m pip install -r /app/reqs.txt")

# --- TRANSITION PATCH FOR 1.3.0 -> 1.3.1 ---
# The old updater.py (1.3.0) contains a bugs (pip.main segfault & touch-reload PyArmor conflict).
# Because the old updater.py is currently in RAM doing the update, it will crash itself if it continues.
# To bypass this, we intercept the update physically *here* (using the newly extracted dbmigrate.py)
# to clean up the zip and kill the uwsgi master. This forces a clean docker container restart 
# with the fixed 1.3.1 files, fully sidestepping the old updater's remaining logic.
try:
    import glob
    import time
    zips = glob.glob("/app/mikroman-pro*.zip")
    if zips:
        print("Update ZIP detected in /app/. Cleaning up and forcing hard restart to bypass old updater logic...")
        for z in zips:
            try:
                os.remove(z)
            except:
                pass
        # Kill uwsgi to force Docker to restart the container cleanly
        os.system("killall -15 uwsgi || kill -15 1")
        time.sleep(10) # Block old updater.py from continuing before the KILL signal arrives
except Exception as e:
    print(f"Error in transition patch: {e}")
