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
log = logging.getLogger("Updater_mule")

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
            # Read and hash the file in 4K chunks. Reading the whole
            # file at once might consume a lot of memory if it is
            # large.
            while True:
                data = fh.read(4096)
                if len(data) == 0:
                    break
                else:
                    h.update(data)
        return expect == h.hexdigest()
    except Exception as e:
        return False

def extract_zip_reload(filename,dst):
    """Extract the contents of the zip file "filename" to the directory
    "dst". Then reload the updated modules."""
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall(dst)
    # run db migrate
    dir ="/app/"
    cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(dir, dir, "/conf/server-conf.json")
    p = subprocess.Popen(cmd, shell=True)
    (output, err) = p.communicate()  
    #This makes the wait possible
    p_status = p.wait()
    #touch server reload file /app/reload
    os.remove(filename)
    Path('/app/reload').touch()



def main():
    while True:
        try:
            from libs import utilpro
            ISPRO=True
        except ImportError:
            ISPRO=False
            pass
        next_hour = (time.time() // 3600 + 1) * 3600
        sleep_time = next_hour - time.time()
        # Code to be executed every hour
        print("Running hourly Update checker ...")
        interfaces = util.get_ethernet_wifi_interfaces()
        hwid = util.generate_serial_number(interfaces)
        username=False
        try:
            username = db_sysconfig.get_sysconfig('username')
        except:
            log.error("No username found")
            time.sleep(300)
            continue
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
        res=False
        url="https://mikrowizard.com/wp-json/mikrowizard/v1/get_update"
        # send post request to server mikrowizard.com with params in json
        try:
            response = requests.post(url, json=params)
            res = response
        except:
            time.sleep(sleep_time)
            continue
        # get response from server
        try:
            if res and res.status_code == 200:
                res=res.json()
            if 'token' in res:
                params={
                "token":res['token'],
                "file_name":res['filename'],
                "username":username.strip()
                }
                log.info("Update available/Downloading...")
            else:
                time.sleep(sleep_time)
                continue
        except Exception as e:
            log.error(e)
        
        # check if  filename exist in /app/ and checksum is same then dont continue
        if check_sha256("/app/"+res['filename'], res['sha256']):
            log.error("Checksum match, File exist")
            extract_zip_reload("/app/"+res['filename'],"/app/")
            time.sleep(sleep_time)
            continue
        download_url="https://mikrowizard.com/wp-json/mikrowizard/v1/download_update"
        # send post request to server mikrowizard.com with params in json
        r = requests.post(download_url,json=params,stream=True)
        if "invalid" in r.text or r.text=='false':
            log.error("Invalid response")
            time.sleep(sleep_time)
            continue
        with open("/app/"+res['filename'], 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
        if check_sha256("/app/"+res['filename'], res['sha256']):
            log.error("Update downloaded : "+"/app/"+res['filename'])
            extract_zip_reload("/app/"+res['filename'],"/app/")
        else:
            log.error("Checksum not match")
            os.remove("/app/"+res['filename'])
        time.sleep(sleep_time)


    
if __name__ == '__main__':
    main()

