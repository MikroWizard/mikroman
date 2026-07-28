#!/usr/bin/python
# -*- coding: utf-8 -*-

# updater.py: independent worker process for updating MikroWizard to latest version
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import time
import datetime
from libs import util
from pathlib import Path
from libs.db import db_sysconfig
import requests
import logging
import os
import hashlib
import zipfile
import subprocess
import json
import uwsgi
log = logging.getLogger("Updater_mule")
import pip
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
def import_or_install(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.run(["python3", "-m", "pip", "install", package])

def install_package(package):
    try:
        subprocess.run(["python3", "-m", "pip", "install", package])
    except Exception as e:
        log.error(e)


def set_get_install_date():
    install_date=False
    try:
        install_date=db_sysconfig.get_sysconfig('install_date')
    except:
        pass
    if not install_date:
        install_date=datetime.datetime.now()
        db_sysconfig.set_sysconfig('install_date',install_date.strftime("%Y-%m-%d %H:%M:%S"))
        install_date=install_date.strftime("%Y-%m-%d %H:%M:%S")
    return install_date

# Example usage
def check_sha256(filename, expect):
    """Check if the file with the name "filename" matches the SHA-256 sum
    in "expect"."""
    h = hashlib.sha256()
    # This will raise an exception if the file doesn't exist. Catching
    # and handling it is left as an exercise for the reader.
    try:
        with open(filename, 'rb') as fh:
            while True:
                data = fh.read(4096)
                if len(data) == 0:
                    break
                else:
                    h.update(data)
        actual = h.hexdigest()
        if expect == actual:
            log.debug("Checksum match for {}: {}".format(filename, actual))
            return True
        else:
            log.warning("Checksum mismatch for {}. Expected: {}, Actual: {}".format(filename, expect, actual))
            return False
    except Exception as e:
        log.error("Error during checksum verification of {}: {}".format(filename, e))
        return False

def extract_zip_reload(filename,dst):
    """Extract the contents of the zip file "filename" to the directory
    "dst". Then reload the updated modules."""
    tmp_extract_dir = "/tmp/mikroman_update"
    
    # Ensure a completely clean slate in case a previous update crashed midway
    subprocess.run("rm -rf {}".format(tmp_extract_dir), shell=True)
    
    log.info("Extracting {} to {}...".format(filename, tmp_extract_dir))
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall(tmp_extract_dir)
        
    log.info("Safely moving files to {}...".format(dst))
    cmd = "cp -aT --remove-destination {} {}".format(tmp_extract_dir, dst)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = p.communicate()
    p_status = p.wait()
    if p_status != 0:
        log.error("Failed to copy update files: {}".format(err.decode().strip()))
        
    subprocess.run("rm -rf {}".format(tmp_extract_dir), shell=True)
    
    # run db migrate
    dir ="/app/"
    cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(dir, dir, "/conf/server-conf.json")
    log.info("Running database migrations: {}".format(cmd))
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = p.communicate()  
    p_status = p.wait()
    if p_status == 0:
        log.info("Database migrations completed successfully.")
    else:
        log.error("Database migrations failed with status {}. Error: {}".format(p_status, err.decode().strip()))

    #install requirements
    try:
        proreqs="/app/py/pro-reqs.txt"
        if os.path.exists(proreqs):
            log.info("Installing PRO requirements from {}...".format(proreqs))
            with open(proreqs, "r") as f:
                for line in f:
                    pkg = line.strip()
                    if pkg and not pkg.startswith("#"):
                        import_or_install(pkg)
                        log.info("Installed PRO package: {}".format(pkg))
                        time.sleep(1)
            time.sleep(3)
    except Exception as e:
        log.error("Error installing PRO requirements: {}".format(e))
        pass

    reqs="/app/reqs.txt"
    if os.path.exists(reqs):
        log.info("Installing standard requirements from {}...".format(reqs))
        with open(reqs, "r") as f:
            for line in f:
                pkg = line.strip()
                if pkg and not pkg.startswith("#"):
                    try:
                        install_package(pkg)
                        log.info("Installed package: {}".format(pkg))
                    except Exception as e:
                        log.error("Failed to install package {}: {}".format(pkg, e))
    
    log.info("Post-update tasks completed. Cleaning up artifact {}.".format(filename))
    os.remove(filename)
    
    # Remove the startup locks so next boot re-verifies requirements
    for f in ["/tmp/mw_pro_lock", "/tmp/mw_pro_done"]:
        if os.path.exists(f):
            os.remove(f)
    
    # Kill the uWSGI master to force a clean, hard container restart.
    # PyArmor requires a clean Python interpreter for new files to prevent memory corruption. 
    masterpid=uwsgi.masterpid()
    log.info("Triggering hard server restart (sending SIGTERM to masterpid: {}).".format(masterpid))
    import signal
    os.kill(masterpid, signal.SIGTERM)

def main():
    while True:
        next_hour = (time.time() // 3600 + 1) * 3600
        sleep_time = next_hour - time.time()
        # Code to be executed every hour
        log.info("Running hourly Update checker ...")
        interfaces = util.get_ethernet_wifi_interfaces()
        hwid = util.generate_serial_number(interfaces)
        update_mode=db_sysconfig.get_sysconfig('update_mode')
        try:
            update_mode=json.loads(update_mode)
        except:
            update_mode={'mode':'auto','update_back':False,'update_front':False}
            db_sysconfig.set_sysconfig('update_mode',json.dumps(update_mode))
        log.debug("Update mode: {}".format(update_mode))
        if update_mode['mode']=='manual':
            if not update_mode['update_back']:
                hwid=hwid+"MANUAL"
                log.info("Update mode is MANUAL, skipping auto-check (HWID: {})".format(hwid))
            else:
                log.info("Manual update triggered.")
                update_mode['update_back']=False
                db_sysconfig.set_sysconfig('update_mode',json.dumps(update_mode))
        username=False
        try:
            username = db_sysconfig.get_sysconfig('username')
        except:
            log.error("No username found")
        # util.send_mikrowizard_request(params)
        if not username or username.strip()=="":
            log.error("No username found")
            time.sleep(300)
            continue
        install_date=set_get_install_date()
        from _version import __version__
        #convert install_date string "%Y-%m-%d %H:%M:%S" to datetime
        install_date = datetime.datetime.strptime(install_date, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
        # convert install_date from "%Y-%m-%d %H:%M:%S" to ""%Y%m%d"" and append to serial_number
        hwid += "-"+install_date
        params={
            "serial_number": hwid,
            "username": username.strip(),
            "version": __version__,
            "ISPRO":ISPRO
        }
        url="https://mikrowizard.com/wp-json/mikrowizard/v1/get_update"
        log.info("Checking for updates at {} with params: {}".format(url, params))
        # send post request to server mikrowizard.com with params in json
        try:
            if os.getenv("DEV_MODE") == "true":
                log.info(f"[DEV_MODE] Params: {params}")
            response = requests.post(url, json=params, timeout=30)
            if response.status_code == 200:
                res = response.json()
                log.debug("Server response (200): {}".format(res))
            else:
                log.warning("Server returned status code: {}".format(response.status_code))
                log.debug("Response body: {}".format(response.text))
                time.sleep(sleep_time)
                continue
        except Exception as e:
            log.error("Error during update check: {}".format(e))
            time.sleep(sleep_time)
            continue
        
        if res and isinstance(res, dict) and 'token' in res:
            params={
                "token":res['token'],
                "file_name":res['filename'],
                "username":username.strip()
            }
            log.info("Update available! Package: {}, SHA256: {}".format(res['filename'], res['sha256']))
        else:
            log.error("res is {}".format(res))
            log.info("No update available or invalid response format from server.")
            time.sleep(sleep_time)
            continue
        
        # check if  filename exist in /app/ and checksum is same then dont continue
        if check_sha256("/app/"+res['filename'], res['sha256']):
            log.error("Checksum match, File exist")
            extract_zip_reload("/app/"+res['filename'],"/app/")
            time.sleep(sleep_time)
            continue
        download_url="https://mikrowizard.com/wp-json/mikrowizard/v1/download_update"
        log.info("Downloading update from {}...".format(download_url))
        # send post request to server mikrowizard.com with params in json
        try:
            r = requests.post(download_url,json=params,stream=True, timeout=60)
            if r.status_code != 200:
                log.error("Download failed with status: {}".format(r.status_code))
                time.sleep(sleep_time)
                continue
            if "invalid" in r.text or r.text=='false':
                log.error("Invalid download response: {}".format(r.text[:100]))
                time.sleep(sleep_time)
                continue
            
            with open("/app/"+res['filename'], 'wb') as fd:
                for chunk in r.iter_content(chunk_size=4096):
                    fd.write(chunk)
            
            log.info("Download complete. Verifying checksum...")
            if check_sha256("/app/"+res['filename'], res['sha256']):
                log.info("Update downloaded and verified: /app/{}".format(res['filename']))
                extract_zip_reload("/app/"+res['filename'],"/app/")
            else:
                log.error("Downloaded file checksum mismatch. Deleting file.")
                os.remove("/app/"+res['filename'])
        except Exception as e:
            log.error("Exception during download: {}".format(e))
        time.sleep(sleep_time)


    
if __name__ == '__main__':
    main()

