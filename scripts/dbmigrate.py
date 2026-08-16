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

# --- UPDATE RESTART PATCH ---
# During an update the running updater mule is still the OLD version loaded in RAM.
# It runs this freshly-extracted dbmigrate.py as a subprocess, so we do the final
# "finish the update" steps HERE, then hard-kill uWSGI to force Docker to restart the
# container with the new files (a clean interpreter is required for PyArmor).
# This sidesteps the old updater's remaining logic (which would otherwise run stale code).
try:
    import glob
    import time
    zips = glob.glob("/app/mikroman*.zip")
    if zips:
        print("Update ZIP detected in /app/. Cleaning up and forcing hard restart...")
        for z in zips:
            try:
                os.remove(z)
            except:
                pass
        # Remove startup locks so the next boot re-verifies/installs requirements.
        # (The old updater would have done this after dbmigrate; we must do it before killing it.)
        for f in ["/tmp/mw_pro_lock", "/tmp/mw_pro_done",
                  "/tmp/mw_init_ai_chat_pro", "/tmp/mw_init_speedtest_pro", "/tmp/mw_init_tickets_pro"]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except:
                pass
        # Hard-kill uWSGI (SIGKILL is unblockable) to force Docker to restart the container cleanly.
        # Fallback to killing PID 1 if killall is missing or matches nothing.
        os.system("killall -9 uwsgi || kill -9 1")
        time.sleep(10) # Block the old updater mule from continuing before the kill signal arrives
except Exception as e:
    print(f"Error in update restart patch: {e}")
