#!/usr/bin/python
# -*- coding: utf-8 -*-

# firm_lib.py: functions that we need :)
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import pytz
import datetime
import time
import socket
import config
from libs.db import db_sysconfig,db_firmware,db_tasks,db_events
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.check_routeros.routeros_check.helper import  RouterOSVersion
from typing import  Dict
import re
import json 
import logging
import os
from bs4 import BeautifulSoup
import urllib.request
import hashlib
log = logging.getLogger("util")
from libs import util
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
import zipfile

def extract_from_link(link,all_package=False):
    try:
        if all_package:
            regex = r"https:\/\/download\.mikrotik\.com\/routeros\/(\d{1,3}.*)?\/all_packages-(.*)-(.*).zip"
            matches = re.match(regex, link)
            if not matches:
                return False
            res=matches.groups()
            version=res[0]
            arch = res[1]
            return {"link":link, "arch":arch, "version":version, "all_package":True}
        else:
            regex = r"https:\/\/download\.mikrotik\.com\/routeros\/(\d{1,3}.*)?\/routeros-(.*).npk"
            matches = re.match(regex,link)
            res=matches.groups()
            version=res[0]
            arch = res[1].replace(version, "")
            if arch == "":
                arch = "x86"
            else:
                arch=arch.replace("-","")
            return {"link":link,"arch":arch, "version":version}
    except Exception as e:
        log.info("unable to extract from link : {}".format(link))
        log.info(e)
        return False
    

def get_mikrotik_latest_firmware_link():
    try:
        html_page = urllib.request.urlopen("https://mikrotik.com/download/")
        soup = BeautifulSoup(html_page, "html.parser")
        firms={}
        for link in soup.findAll('a'):
            link=str(link.get('href'))
            if ".npk" in link:
                frimware=extract_from_link(link)
                if not frimware:
                    continue
                firms.setdefault(frimware["version"],{})
                firms[frimware["version"]][frimware["arch"]]={"link":frimware["link"],"mark":"latest"}
                # firms.append(link)
        return firms
    except Exception as e:
        log.error(e)
        return False

def get_mikrotik_download_links(version,all_package=False):
    try:
        log.info("Downloading firmwares from https://mikrotik.com/download/archive?v={}".format(version))
        html_page = urllib.request.urlopen("https://mikrotik.com/download/archive?v={}".format(version))
        soup = BeautifulSoup(html_page, "html.parser")
        firms={}
        for trs in soup.findAll('tr'):
            link=trs.findAll('a')
            if len(link):
                lnk=str(link[0].get('href'))
                sha=str(link[1].get('data-checksum-sha256'))
                if ".npk" in lnk:
                    log.error(lnk)
                    frimware=extract_from_link(lnk)
                    if not frimware:
                        continue
                    firms.setdefault(frimware["version"], {})
                    firms[frimware["version"]][frimware["arch"]]={"link":frimware["link"],"sha":sha}
                    # firms.append(link)
                elif all_package and ".zip" in lnk:
                    frimware=extract_from_link(lnk, all_package=all_package)
                    if not frimware:
                        continue
                    firms.setdefault(frimware["version"], {})
                    firms[frimware["version"]][frimware["arch"]+"-"+"allpackage"]={"link":frimware["link"],"sha":sha}
        return firms
    except Exception as e:
        log.error(e)
        return False    

def get_mikrotik_versions():
    try:
        html_page = urllib.request.urlopen("https://mikrotik.com/download/archive")
        soup = BeautifulSoup(html_page, "html.parser")
        versions=[]
        for link in soup.findAll('a'):
            ver=link.find("strong")
            if ver:
                versions.append(ver.text)
        try:
            vers=list(get_mikrotik_latest_firmware_link().keys())
            if versions and vers:
                unique_elements = set(versions + vers)
                versions = list(unique_elements)
            elif not versions and vers:
                if vers:
                    versions = vers
        except Exception as e:
            log.error(e)
            pass
        return versions
    except Exception as e:
        log.error(e)
        return False

def check_sha256(path,sha256=False):
    hash_obj = hashlib.sha256()
    if not sha256 and os.path.exists(path):
        with open(path, 'rb') as f:
            hash_obj.update(f.read())
        return hash_obj.hexdigest()
    elif os.path.exists(path) and sha256:
        with open(path, 'rb') as f:
            hash_obj.update(f.read())
        return hash_obj.hexdigest() == sha256
    else:
        return False 

def web2file(url, filePath,sha256=False, tries=3, timeout=3, sleepBetween=1):
    tempPath = filePath
    status=False
    if os.path.exists(tempPath) and sha256:
        hash_obj = hashlib.sha256()
        with open(tempPath, 'rb') as f:
            hash_obj.update(f.read())
        if hash_obj.hexdigest() == sha256:
            log.error("File already exists : {}".format(filePath))
            return True
    failures = 0
    while True:
        tries=tries-1
        if failures == tries:
            try:
                os.remove(tempPath)
            except:
                pass
        try:
            socket.setdefaulttimeout(timeout)
            urllib.request.urlretrieve(url, tempPath)
            if sha256:
                hash_obj = hashlib.sha256()
                with open(tempPath, 'rb') as f:
                    hash_obj.update(f.read())
                if hash_obj.hexdigest() == sha256:
                    status=True
                    break
            else:
                status=True
                break
        except urllib.error.HTTPError:
            log.error("HTTP Error")
        except urllib.error.URLError:
            time.sleep(sleepBetween)
        except TimeoutError:
            pass
        except socket.timeout:
            pass
    return status
def extract_zip (file,path):
    #extract and return file names from zip file
    try:
        with zipfile.ZipFile(file, 'r') as zip_ref:
            zip_ref.extractall(path)
            names=zip_ref.namelist()
        return names
    except Exception as e:
        log.error(e)
        
def download_firmware_to_repository(version,q,arch="all",all_package=True):
    #repository='/app/firms/'
    repository=config.FIRM_DIR
    #create direcorty version in repository if not exist
    path=repository+version+"/"
    os.makedirs(path, exist_ok=True)
    # try:
    if all_package:
        #download all_packages
        links=get_mikrotik_download_links(version,all_package=all_package)
    else:
        links=get_mikrotik_download_links(version)
    if links:
        links=links[version]
        firm=db_firmware.Firmware()
        for lnk in links:
            task=db_tasks.downloader_job_status()
            if task.action=="cancel":
                log.info("Firmware Download Task Canceled")
                if q:
                    q.put({"status":False})
                return False
            if all_package and "-allpackage" in lnk == lnk:
                arch_togo=lnk.split("-allpackage")[0]
                link=links[lnk]["link"]
                sha256=links[lnk]["sha"]
                file=path+"all_packages-" + arch_togo + ".zip"
                done=web2file(link, file, sha256=sha256)
                files=extract_zip(file, path)
                try:
                    if done and len(files)>0:
                        for f in files:
                            file=path+f
                            sha256=check_sha256(file)
                            firm.insert(version=version, location=file, architecture=arch_togo+"-"+f.split("-{}".format(version))[0], sha256=sha256).on_conflict(conflict_target=['version', 'architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status":True})
                # return True
                continue
            if arch!="all" and arch==lnk:
                arch_togo=lnk
                link=links[lnk]["link"]
                sha256=links[lnk]["sha"]
                file=path+"{}.npk".format(arch_togo)
                done=web2file(link, file,sha256=sha256)
                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version','architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status":True})
                continue
                # return True
            if arch=="all":
                #download file to path and check sha265 
                arch_togo=lnk
                link=links[lnk]["link"]
                sha256=links[lnk]["sha"]
                file=path+"{}.npk".format(arch_togo)
                done=web2file(link, file,sha256=sha256)
                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version','architecture'], preserve=['location', 'architecture', 'version'], update={'sha256':sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
        if q:
            q.put({"status":True})
        return True
    else:
        if q:
            q.put({"status":False})
        return False
    # except Exception as e:
    #     log.error(e)
    #     if q:
    #         q.put({"status":True})
    #     return False


def update_device(dev,q):
    events=list(db_events.get_events_by_src_and_status("updater", 0,dev.id).dicts())
    ofa=db_sysconfig.get_firmware_action().value
    _installed_version=RouterOSVersion(dev.current_firmware)
    try:
        if not dev.firmware_to_install and dev.upgrade_device:
            #just do upgrade
            ver_to_install=_installed_version
        else:
            if dev.firmware_to_install:
                ver_to_install=dev.firmware_to_install
            elif ofa=="keep" and _installed_version < RouterOSVersion('7.0.0'):
                ver_to_install=db_sysconfig.get_firmware_old().value
            else:
                ver_to_install=db_sysconfig.get_firmware_latest().value
            ver_to_install = RouterOSVersion(ver_to_install)
            
    except Exception as e:
        log.error(e)
        q.put({"id": dev.id})
        return False
    arch=dev.arch
    if "x86" in arch:
        arch="x86"
    if not dev.firmware_to_install or RouterOSVersion(dev.firmware_to_install)!=ver_to_install:
        dev.firmware_to_install=ver_to_install
        dev.save()
    try:
        if _installed_version==ver_to_install:
            util.check_or_fix_event(events,"firmware","Update Failed")
            util.check_or_fix_event(events,"firmware","Firmware repositpry")
            util.check_or_fix_event(events,"firmware","Device storage")
            dev.firmware_to_install=None
            if dev.upgrade_device and dev.status != "failed":
                dev.failed_attempt=0
                dev.status = "upgrading"
                dev.save()
                upgrade_routerboot(dev, q)
            elif dev.upgrade_device and dev.status == "failed":
                dev.failed_attempt+=1
                dev.status = "failed"
                dev.save()
                upgrade_routerboot(dev, q)
            else:
                dev.failed_attempt=0
                dev.status = 'updated'
                dev.save()
            q.put({"id": dev.id})
            return True
    except Exception as e:
        log.error(e)
        pass
    #get correct firmware from db for updating
    firm=False
    firm2=False
    if ISPRO:
        firm,firm2=utilpro.safe_check(dev,_installed_version,ver_to_install)
    elif arch and arch!='':
        firm=db_firmware.get_frim_by_version(ver_to_install, arch)
    else:
        q.put({"id": dev.id})
    options=util.build_api_options(dev)
    #get /system package print 
    router=RouterOSCheckResource(options) 
    try:
        call=router.api.path('/system/package')
        results = tuple(call)
    except:
        q.put({"id": dev.id})
        return False
    packages=[]
    if firm:
        packages.append(firm)
    else:
        db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"Firmware not found #2 :Please check firmware config in settings section")
        log.error('No Firmware found for device {}({})'.format(dev.name,dev.ip))
        q.put({"id": dev.id})
        return False
    
    for res in results:
        if res['name']!="routeros":
            package=db_firmware.get_frim_by_version(ver_to_install, "{}-{}".format(arch,res['name']))
            if package:
                packages.append(package)

    try:
        #Try to take a backup from the router before update
        try:
            util.backup_router(dev)
        except:
            pass
        apply_firmware(packages, firm2, arch, dev, router, events, q)
    except:
        q.put({"id": dev.id})

def apply_firmware(packages,firm2,arch,dev,router,events,q):
    dev.failed_attempt=dev.failed_attempt+1
    if dev.failed_attempt > 3:
        db_events.firmware_event(dev.id,"updater","Update Failed","Critical",0,"Unable to Update device")
        dev.save()
        q.put({"id": dev.id})
        return False
    dev.status="updating"
    dev.save()
    try:
        url=dev.peer_ip
        api = router._connect_api()
        if not url:
            url=db_sysconfig.get_sysconfig('system_url')
        if not "http" in url:
            url="http://"+url
        if firm2:
            url_firm2=url+"/api/firmware/get_firmware/{}".format(firm2.id)
            params = {"url": url_firm2,"keep-result":"yes","dst-path":firm2.architecture+".npk"}
            cmd='/tool/fetch'
            call = api(cmd,**params)
            results = tuple(call)
            result: Dict[str, str] = results[-1]
            if result['status'] != 'finished':
                dev.status="failed"
                dev.save()
                q.put({"id": dev.id})
                return False
        for package in packages:
            url_package=url+"/api/firmware/get_firmware/{}".format(package.id)
            params = {"url": url_package,"keep-result":"yes","dst-path":package.architecture+".npk"}
            cmd='/tool/fetch'
            call = api(cmd, **params)
            results = tuple(call)
            log.warning(results)
            result: Dict[str, str] = results[-1]
            if result['status'] != 'finished':
                log.error("There is a problem with downloading of Firmware in device")
                dev.status="failed"
                dev.save()
                db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"There is a problem with downloading of Firmware in device")
                q.put({"id": dev.id})
                return False
        util.check_or_fix_event(events,"firmware","Device storage")
        cmd='/system/reboot'
        call = api(cmd)
        rebootresults = tuple(call)
        log.warning(rebootresults)
        util.check_or_fix_event(events,"firmware","Firmware repositpry")
        dev.status="updated"
        dev.save()
    except Exception as e:
        dev.status="failed"
        dev.save()
        if 'no space left' in str(e):
            db_events.firmware_event(dev.id,"updater","Device storage","Error",0,"There is not enogh space in device storage")
        if '404 Not Found' in str(e):
            db_events.firmware_event(dev.id,"updater","Firmware repositpry","Error",0,"Firmware not found #1 :Please check firmware config in settings section")
        log.error(e)
        q.put({"id": dev.id})
    q.put({"id": dev.id})


def upgrade_routerboot(dev, q=None):
    success = False
    options = util.build_api_options(dev)
    router = RouterOSCheckResource(options)
    api = None
    try:
        api = router._connect_api()
        # Perform upgrade directly
        log.info("Performing RouterBOOT firmware upgrade...")
        cmd_upgrade = '/system/routerboard/upgrade'
        call_upgrade = api(cmd_upgrade)
        upgraderesults = tuple(call_upgrade)
        log.warning(upgraderesults)  # e.g., [{'!done': True}, {'message': 'Firmware upgraded successfully'}]

        # Reboot to apply
        try:
            log.info("Performing RouterBOOT Reboot...")
            cmd_reboot = '/system/reboot'
            call_reboot = api(cmd_reboot)
            rebootresults = tuple(call_reboot)
            log.warning(rebootresults)
        except Exception as e:
            log.error(f"Error during RouterBOOT Reboot: {e}")
        dev.upgrade_device = False
        dev.save()
        success = True

    except Exception as e:
        log.error(f"Error during RouterBOOT upgrade: {e}")
        if "no such command" in str(e):
            db_events.firmware_event(dev.id, "updater", "Firmware Upgrade", "Error", 0, "RouterBOOT upgrade command not found")
            dev.status = "updated"
            dev.upgrade_device = False
        else:
            db_events.firmware_event(
                dev.id, "updater", "Firmware Upgrade", "Error", 0, 
                f"Failed to upgrade RouterBOOT: {str(e)}"
            )
            dev.status = "failed"
        dev.save()
        success = False

    finally:
        if api:
            api.close()

    # Update status and queue
    if success:
        dev.status = "updated"
        # Optional: Reset upgrade flag
        dev.upgrade_device = False
    else:
        dev.status = "failed"
    dev.save()
    if q:
        q.put({"id": dev.id})
    return success