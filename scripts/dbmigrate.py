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
        # Hard-kill uWSGI processes to force Docker to restart the container cleanly.
        # Pure-Python implementation: does NOT depend on killall or pkill being installed!
        import signal

        # 1. Kill parent process (the updater mule)
        try:
            os.kill(os.getppid(), signal.SIGKILL)
        except Exception:
            pass

        # 2. Pure Python /proc scan: kill all processes running uwsgi
        try:
            my_pid = os.getpid()
            for pid_dir in os.listdir('/proc'):
                if pid_dir.isdigit():
                    pid = int(pid_dir)
                    if pid not in (1, my_pid):
                        try:
                            with open(f'/proc/{pid}/cmdline', 'rb') as cf:
                                if b'uwsgi' in cf.read():
                                    os.kill(pid, signal.SIGKILL)
                        except Exception:
                            pass
        except Exception:
            pass

        # 3. Fallback to shell tools if present
        try:
            os.system("pkill -9 -f uwsgi 2>/dev/null || killall -9 uwsgi 2>/dev/null")
        except:
            pass

        time.sleep(10)
except Exception as e:
    print(f"Error in update restart patch: {e}")
