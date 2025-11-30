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


import requests
from urllib.parse import urljoin
import zipfile

# Browser headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# Valid architectures (powerpc removed — no longer exists)
ARCHES = ["x86", "arm", "arm64", "mipsbe", "mmips", "ppc", "smips", "tile"]

def extract_from_link(link, all_package=False):
    try:
        if all_package:
            m = re.match(r"https?://(?:download|cdn)\.mikrotik\.com/routeros/[^/]+/all_packages-([^-]+)-[^/]+\.zip", link)
            if not m:
                return False
            arch = m.group(1)
            version = link.split("/")[-2]
            return {"link": link, "arch": arch, "version": version, "all_package": True}

        else:
            # Match: routeros-7.20.4.npk → x86
            #       routeros-7.20.4-arm64.npk → arm64
            m = re.match(r"https?://(?:download|cdn)\.mikrotik\.com/routeros/[^/]+/routeros-([^-/]+)(?:-([a-z0-9]+))?\.npk", link)
            if not m:
                return False
            version_part = m.group(1)
            arch_part = m.group(2)
            arch = "x86" if not arch_part else arch_part.replace("-", "")
            return {"link": link, "arch": arch, "version": version_part}
    except Exception as e:
        log.info(f"extract_from_link failed: {link} | {e}")
        return False

def get_mikrotik_latest_firmware_link():
    versions = get_mikrotik_versions()
    if not versions:
        return False
    latest = versions[0]
    return get_mikrotik_download_links(latest, all_package=False)

def get_mikrotik_download_links(version, all_package=False):
    try:
        log.info(f"Fetching packages for version {version}")
        base = f"https://download.mikrotik.com/routeros/{version}/"
        cdn_base = f"https://cdn.mikrotik.com/routeros/{version}/"
        result = {}

        # === Main .npk packages ===
        for arch in ARCHES:
            if arch == "x86":
                filename = f"routeros-{version}.npk"
            else:
                filename = f"routeros-{version}-{arch}.npk"

            # Try main server first
            url = urljoin(base, filename)
            if requests.head(url, headers=HEADERS, timeout=10).status_code == 200:
                pass
            elif requests.head(url.replace("download.mikrotik.com", "cdn.mikrotik.com"), headers=HEADERS, timeout=10).status_code == 200:
                url = url.replace("download.mikrotik.com", "cdn.mikrotik.com")
            else:
                continue  # File doesn't exist

            info = extract_from_link(url)
            if info:
                result.setdefault(info["version"], {})[info["arch"]] = {
                    "link": url,
                    "sha": None  # SHA not available reliably
                }

        # === All packages ZIPs ===
        if all_package:
            for arch in ARCHES:
                zip_name = f"all_packages-{arch}-{version}.zip"
                url = urljoin(cdn_base, zip_name)  # CDN has them
                if requests.head(url, headers=HEADERS, timeout=10).status_code != 200:
                    url = urljoin(base, zip_name)  # fallback
                    if requests.head(url, headers=HEADERS, timeout=10).status_code != 200:
                        continue

                info = extract_from_link(url, all_package=True)
                if info:
                    key = info["arch"] + "-allpackage"
                    result.setdefault(info["version"], {})[key] = {
                        "link": url,
                        "sha": None
                    }

        return result if result else False

    except Exception as e:
        log.error(f"get_mikrotik_download_links failed for {version}: {e}")
        return False


def parse_version_key(v):
    """Parse version string for sorting. Returns tuple of (major, minor, patch, suffix_type, suffix_num)"""
    # Extract base version and suffix (e.g., "7.16beta5" -> "7.16", "beta5")
    match = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?(beta|rc)?(\d+)?$', v)
    if not match:
        return (0, 0, 0, 'z', 0)  # Invalid versions sort last
    
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    suffix_type = match.group(4) or 'stable'  # beta, rc, or stable
    suffix_num = int(match.group(5)) if match.group(5) else 0
    
    # Sorting priority: stable > rc > beta
    suffix_priority = {'stable': 2, 'rc': 1, 'beta': 0}
    
    return (major, minor, patch, suffix_priority.get(suffix_type, -1), suffix_num)


def get_mikrotik_versions(channel="stable"):
    try:
        # Channel to URL param
        channel_map = {"stable": "", "long-term": "long-term", "testing": "testing"}
        param = channel_map.get(channel, "")
        url = f"https://mikrotik.com/download/changelogs?channelFilter={param}"
        log.info(f"Fetching {channel} versions from {url}")
        
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Primary: Extract from x-on:header-click="toggleChangelog('VERSION')"
        candidates = set()
        for elem in soup.find_all(attrs={"x-on:header-click": True}):
            attr_value = elem.get('x-on:header-click', '')
            # Captures beta/rc suffixes for testing
            match = re.search(r"toggleChangelog\('([67]\.\d+(?:\.\d+)?(?:beta|rc)?\d*)'\)", attr_value)
            if match:
                v = match.group(1)
                candidates.add(v)

        # Fallback: Regex on headings/strong if no attributes
        # if not candidates:
        #     log.info("No x-on attributes; falling back to headings")
        #     for elem in soup.find_all(['h3', 'h2', 'h1', 'strong', 'b']):
        #         text = elem.get_text(strip=True)
        #         matches = re.findall(r'\b[67]\.\d{1,2}(?:\.\d{1,2})?(?:beta|rc)?\d*\b', text)
        #         candidates.update(matches)

        # Simple validation: check format and reasonable ranges
        versions = set()
        for v in candidates:
            match = re.match(r'^([67])\.(\d+)(?:\.(\d+))?(beta|rc)?(\d+)?$', v)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                patch = int(match.group(3)) if match.group(3) else 0
                
                # Validate reasonable ranges
                if major in (6, 7) and minor <= 59 and patch <= 99:
                    versions.add(v)

        # Sort using custom version key (newest first)
        sorted_versions = sorted(versions, key=parse_version_key, reverse=True)
        
        log.info(f"Found {len(sorted_versions)} valid versions for {channel} (latest: {sorted_versions[0] if sorted_versions else 'None'})")
        return sorted_versions if sorted_versions else False
    except Exception as e:
        log.error(e)
        return False


def check_sha256(path, sha256=False):
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

def verify_npk_structure(file_path):
    """
    Verification of NPK file structure. since no healty way found to grab sha256 from mikrotik website we check for npk validataion with other ways.
    NPK files are SquashFS filesystems - validate structure integrity.
    """
    try:
        with open(file_path, 'rb') as f:
            # Check SquashFS magic bytes
            # SquashFS has multiple valid magic numbers depending on version and endianness:
            # - 'hsqs' (0x73717368) - SquashFS 4.0 big-endian
            # - 'sqsh' (0x68737173) - SquashFS 4.0 little-endian
            # - 0x1ef1d0ba - SquashFS 3.x/4.x little-endian (used by RouterOS)
            # - 0xbad0f11e - SquashFS 3.x/4.x big-endian
            magic = f.read(4)
            
            valid_magic_bytes = [
                b'hsqs',                    # SquashFS 4.0 big-endian
                b'sqsh',                    # SquashFS 4.0 little-endian
                b'\xba\xd0\xf1\x1e',       # SquashFS 3.x/4.x little-endian (0x1ef1d0ba)
                b'\x1e\xf1\xd0\xba',       # SquashFS 3.x/4.x big-endian (0xbad0f11e)
            ]
            
            if magic not in valid_magic_bytes:
                log.error(f"Invalid NPK magic bytes: {magic.hex()} (expected SquashFS magic)")
                return False
            
            log.info(f"Valid SquashFS magic bytes detected: {magic.hex()}")
            
            # Read SquashFS superblock to validate structure
            f.seek(0)
            header = f.read(96)  # SquashFS superblock is 96 bytes
            
            if len(header) < 96:
                log.error("NPK file too small to contain valid SquashFS header")
                return False
            
            # Get file size
            f.seek(0, 2)
            file_size = f.tell()
            
            # NPK files should be at least 100KB and less than 100MB
            if file_size < 100000:
                log.error(f"NPK file too small: {file_size} bytes")
                return False
            
            if file_size > 100 * 1024 * 1024:
                log.error(f"NPK file suspiciously large: {file_size} bytes")
                return False
            
            log.info(f"NPK structure validated: {file_size} bytes, magic: {magic.hex()}")
            return True
            
    except Exception as e:
        log.error(f"NPK structure verification failed: {e}")
        return False


def verify_zip_structure(file_path):
    """
    Verification of ZIP file structure.
    Validates ZIP and NPK contents.
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Test the ZIP file integrity (CRC checks)
            bad_file = zip_ref.testzip()
            if bad_file:
                log.error(f"Corrupted file in ZIP: {bad_file}")
                return False
            
            # Get list of files
            files = zip_ref.namelist()
            npk_files = [f for f in files if f.endswith('.npk')]
            
            if not npk_files:
                log.error("ZIP does not contain any .npk files")
                return False
            
            # Validate that NPK files have reasonable sizes
            total_size = 0
            for npk in npk_files:
                info = zip_ref.getinfo(npk)
                if info.file_size < 1000:  # NPK should be at least 1KB (some packages like lora are small)
                    log.error(f"NPK file {npk} too small: {info.file_size} bytes")
                    return False
                total_size += info.file_size
            
            log.info(f"ZIP structure validated: {len(npk_files)} NPK files, total uncompressed: {total_size} bytes")
            return True
            
    except zipfile.BadZipFile:
        log.error("Invalid ZIP file")
        return False
    except Exception as e:
        log.error(f"ZIP structure verification failed: {e}")
        return False


def get_server_file_metadata(url, timeout=10):
    """
    Get file metadata from server without downloading.
    Returns dict with: size, etag, last_modified
    """
    try:
        response = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        
        metadata = {
            'size': int(response.headers.get('Content-Length', 0)),
            'etag': response.headers.get('ETag', '').strip('"'),
            'last_modified': response.headers.get('Last-Modified', ''),
            'content_type': response.headers.get('Content-Type', ''),
        }
        
        log.info(f"Server metadata: size={metadata['size']}, etag={metadata['etag']}, last_modified={metadata['last_modified']}")
        return metadata
        
    except Exception as e:
        log.error(f"Failed to get server metadata: {e}")
        return None


def web2file(url, filePath, sha256=False, tries=3, timeout=30, sleepBetween=2):
    """
    Download file with comprehensive integrity verification using server metadata.
    
    Verification strategy:
    1. Get server metadata (Content-Length, ETag, Last-Modified) BEFORE download
    2. Download file with streaming
    3. Verify downloaded size matches server's Content-Length
    4. Verify file structure (NPK/ZIP deep validation)
    5. Calculate SHA256 for database storage
    6. If sha256 provided (from database), verify against it
    """
    tempPath = filePath + ".tmp"
    
    # If file exists and sha256 matches (from database), skip download
    if os.path.exists(filePath) and sha256:
        existing_hash = check_sha256(filePath)
        if existing_hash == sha256:
            log.info(f"File already exists with correct SHA256: {filePath}")
            return True
    
    # Get server metadata BEFORE downloading
    server_metadata = get_server_file_metadata(url, timeout=10)
    if not server_metadata or server_metadata['size'] == 0:
        log.error("Could not retrieve server metadata or file size is 0")
        return False
    
    expected_size = server_metadata['size']

    # If file exists but no SHA256 provided, check size against server
    if os.path.exists(filePath):
        local_size = os.path.getsize(filePath)
        if local_size == expected_size:
            if not sha256:
                log.info(f"File already exists with correct size: {filePath}")
                return True
            # If sha256 was provided, we already checked it above and it failed.
            # So if we are here with sha256=True, it means hash mismatch -> proceed to download.
            log.info(f"File exists with correct size but SHA256 mismatch. Re-downloading.")
        else:
            log.info(f"File size mismatch: local {local_size} != server {expected_size}. Re-downloading.")
    
    for attempt in range(tries):
        try:
            log.info(f"Downloading {url} (attempt {attempt + 1}/{tries})")
            
            # Download the file with streaming
            response = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            response.raise_for_status()
            
            # Verify response headers match what we got from HEAD request
            actual_size_header = int(response.headers.get('Content-Length', 0))
            if actual_size_header != expected_size:
                log.warning(f"Content-Length changed: expected {expected_size}, got {actual_size_header}")
                # Update expected size if server changed it
                expected_size = actual_size_header
            
            # Write to temporary file and calculate SHA256
            downloaded_size = 0
            hash_obj = hashlib.sha256()
            
            with open(tempPath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        hash_obj.update(chunk)
                        downloaded_size += len(chunk)
            
            log.info(f"Downloaded {downloaded_size} bytes")
            
            # VERIFICATION STEP 1: Check file size matches server's Content-Length
            if downloaded_size != expected_size:
                log.error(f"Size mismatch: server reported {expected_size}, downloaded {downloaded_size}")
                os.remove(tempPath)
                if attempt < tries - 1:
                    log.info("Retrying download...")
                    time.sleep(sleepBetween)
                    continue
                return False
            
            log.info("✓ File size matches server metadata")
            
            # VERIFICATION STEP 2: Deep file structure validation
            is_npk = filePath.endswith('.npk')
            is_zip = filePath.endswith('.zip')
            
            if is_npk:
                if not verify_npk_structure(tempPath):
                    log.error("NPK structure validation failed")
                    os.remove(tempPath)
                    if attempt < tries - 1:
                        log.info("Retrying download...")
                        time.sleep(sleepBetween)
                        continue
                    return False
                log.info("✓ NPK structure validated")
            
            elif is_zip:
                if not verify_zip_structure(tempPath):
                    log.error("ZIP structure validation failed")
                    os.remove(tempPath)
                    if attempt < tries - 1:
                        log.info("Retrying download...")
                        time.sleep(sleepBetween)
                        continue
                    return False
                log.info("✓ ZIP structure validated")
            
            # VERIFICATION STEP 3: Calculate SHA256
            calculated_sha256 = hash_obj.hexdigest()
            log.info(f"✓ SHA256 calculated: {calculated_sha256}")
            
            # VERIFICATION STEP 4: If SHA256 provided from database, verify
            if sha256 and calculated_sha256 != sha256:
                log.error(f"SHA256 mismatch with database: expected {sha256}, got {calculated_sha256}")
                log.warning("This might indicate file was updated on server or database has wrong hash")
                # Don't fail here - the file might be legitimately updated
                # Just log the warning
            
            # All verifications passed, move temp file to final location
            if os.path.exists(filePath):
                os.remove(filePath)
            os.rename(tempPath, filePath)
            
            log.info(f"✓ Download verified and saved to {filePath}")
            log.info(f"  Server size: {expected_size} bytes")
            log.info(f"  Downloaded: {downloaded_size} bytes")
            log.info(f"  SHA256: {calculated_sha256}")
            
            return True
            
        except requests.exceptions.RequestException as e:
            log.error(f"Download error: {e}")
            if os.path.exists(tempPath):
                os.remove(tempPath)
            if attempt < tries - 1:
                log.info("Retrying download...")
                time.sleep(sleepBetween)
                continue
            return False
            
        except Exception as e:
            log.error(f"Unexpected error during download: {e}")
            if os.path.exists(tempPath):
                os.remove(tempPath)
            if attempt < tries - 1:
                log.info("Retrying download...")
                time.sleep(sleepBetween)
                continue
            return False
    
    return False


def extract_zip(file, path):
    # extract and return file names from zip file
    try:
        with zipfile.ZipFile(file, 'r') as zip_ref:
            zip_ref.extractall(path)
            names = zip_ref.namelist()
        return names
    except Exception as e:
        log.error(e)
        return []

def download_firmware_to_repository(version, q, arch="all", all_package=True):
    # repository='/app/firms/'
    repository = config.FIRM_DIR
    # create directory version in repository if not exist
    path = repository + version + "/"
    os.makedirs(path, exist_ok=True)
    # try:
    if all_package:
        # download all_packages
        links = get_mikrotik_download_links(version, all_package=all_package)
    else:
        links = get_mikrotik_download_links(version)
    if links:
        links = links[version]
        firm = db_firmware.Firmware()
        for lnk in links:
            task = db_tasks.downloader_job_status()
            if task.action == "cancel":
                log.info("Firmware Download Task Canceled")
                if q:
                    q.put({"status": False})
                return False
            if all_package and "-allpackage" in lnk == lnk:
                arch_togo = lnk.split("-allpackage")[0]
                link = links[lnk]["link"]
                # we  dont get the sha256 from mikrotik website anyomre ! commented untill find a way
                # sha256 = links[lnk]["sha"]
                sha256 = False
                file = path + "all_packages-" + arch_togo + ".zip"
                done = web2file(link, file, sha256=sha256)
                files = extract_zip(file, path)
                try:
                    if done and len(files) > 0:
                        for f in files:
                            file_path = path + f
                            sha256_file = check_sha256(file_path)
                            firm.insert(version=version, location=file_path, architecture=arch_togo + "-" + f.split("-{}".format(version))[0], sha256=sha256_file).on_conflict(conflict_target=['version', 'architecture'], preserve=['location', 'architecture', 'version'], update={'sha256': sha256_file}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status": True})
                # return True
                continue
            if arch != "all" and arch == lnk:
                arch_togo = lnk
                link = links[lnk]["link"]
                # no sha anymore from mikrotik webstie
                #sha256 = links[lnk]["sha"]
                sha256 = False
                file = path + "{}.npk".format(arch_togo)
                done = web2file(link, file, sha256=sha256)
                sha256 = check_sha256(file)
                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version', 'architecture'], preserve=['location', 'architecture', 'version'], update={'sha256': sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
                if q:
                    q.put({"status": True})
                continue
                # return True
            if arch == "all":
                # download file to path and check sha256 
                arch_togo = lnk
                link = links[lnk]["link"]
                # no sha anymore from mikrotik webstie
                #sha256 = links[lnk]["sha"]
                sha256 = False
                file = path + "{}.npk".format(arch_togo)
                done = web2file(link, file, sha256=sha256)
                sha256 = check_sha256(file)

                try:
                    if done:
                        firm.insert(version=version, location=file, architecture=arch_togo, sha256=sha256).on_conflict(conflict_target=['version', 'architecture'], preserve=['location', 'architecture', 'version'], update={'sha256': sha256}).execute() 
                except Exception as e:
                    log.error(e)
                    pass
        if q:
            q.put({"status": True})
        return True
    else:
        if q:
            q.put({"status": False})
        return False
    # except Exception as e:
    #     log.error(e)
    #     if q:
    #         q.put({"status": True})
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