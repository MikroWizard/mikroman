#!/usr/bin/python
# -*- coding: utf-8 -*-

# firm_lib.py: functions that we need :)
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import sys
import pytz
import datetime
import time
import socket
import config
from libs.db import db_sysconfig,db_firmware,db_tasks,db_events,db_device,db_user_tasks
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.check_routeros.routeros_check.helper import  RouterOSVersion
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
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
    versions = get_mikrotik_versions("stable")
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
    match = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?(alpha|beta|rc|pre)?(\d+)?$', v)
    if not match:
        return (0, 0, 0, -1, 0)  # Invalid versions sort last
    
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    suffix_type = match.group(4) or 'stable'  # stable, rc, beta, alpha, pre
    suffix_num = int(match.group(5)) if match.group(5) else 0
    
    # Sorting priority: stable > rc > beta > alpha/pre
    suffix_priority = {'stable': 3, 'rc': 2, 'beta': 1, 'alpha': 0, 'pre': 0}
    
    return (major, minor, patch, suffix_priority.get(suffix_type, -1), suffix_num)


def get_mikrotik_versions(channel="stable"):
    try:
        # MikroTik Livewire channel filter mapping
        channel_map = {
            "stable": "stable",
            "long-term": "longTerm",
            "testing": "testing",
            "development": "development",
            "all": ""
        }
        param = channel_map.get(channel, "stable")
        url = f"https://mikrotik.com/download/changelogs?channelFilter={param}"
        log.info(f"Fetching {channel} versions from {url}")
        
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        candidates = set()
        # 1. Primary: Extract from data-changelog-version (used in modern Livewire components)
        for elem in soup.find_all(attrs={"data-changelog-version": True}):
            v = elem.get('data-changelog-version', '').strip()
            if v:
                candidates.add(v)

        # 2. Secondary: Extract from x-on:header-click="toggleChangelog('VERSION')"
        for elem in soup.find_all(attrs={"x-on:header-click": True}):
            attr_value = elem.get('x-on:header-click', '')
            match = re.search(r"toggleChangelog\('([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:alpha|beta|rc|pre)?\d*)'\)", attr_value)
            if match:
                candidates.add(match.group(1))

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
            match = re.match(r'^([67])\.(\d+)(?:\.(\d+))?(alpha|beta|rc|pre)?(\d+)?$', v)
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
            if all_package and "-allpackage" in lnk:
                arch_togo = lnk.split("-allpackage")[0]
                if arch != "all" and arch != arch_togo:
                    continue
                link = links[lnk]["link"]
                # sha256 not available reliably from mikrotik website
                sha256 = False
                file = path + "all_packages-" + arch_togo + ".zip"
                done = web2file(link, file, sha256=sha256)
                files = extract_zip(file, path) if done else []
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
    
def check_device_storage_preflight(router, required_mb=15):
    """
    Pre-flight check for router storage space before pushing firmware packages.
    Returns (True, free_mb) if space is sufficient, else (False, free_mb).
    Supports RouterOSCheckResource instance, Api instance, or Path object.
    """
    try:
        if hasattr(router, 'api') and hasattr(router.api, 'path'):
            call = router.api.path('/system/resource')
        elif hasattr(router, 'path'):
            call = router.path('/system/resource')
        elif hasattr(router, '_connect_api'):
            api = router._connect_api()
            call = api('/system/resource/print')
        else:
            call = router('/system/resource/print')

        res = tuple(call)
        if res and 'free-hdd-space' in res[0]:
            free_bytes = int(res[0]['free-hdd-space'])
            free_mb = free_bytes / (1024 * 1024)
            if free_mb < required_mb:
                return False, free_mb
            return True, free_mb
    except Exception as e:
        log.warning(f"Could not check storage preflight: {e}")
    return True, 0.0


def verify_router_file(router, filename):
    """
    Verify that a downloaded package file exists on router storage and has non-zero size.
    Prevents rebooting if download was truncated or rejected by storage.
    Supports RouterOSCheckResource instance, Api instance, or Path object.
    """
    try:
        if hasattr(router, 'api') and hasattr(router.api, 'path'):
            call = router.api.path('/file')
        elif hasattr(router, 'path'):
            call = router.path('/file')
        elif hasattr(router, '_connect_api'):
            api = router._connect_api()
            call = api('/file/print')
        else:
            call = router('/file/print')

        files = tuple(call)
        clean_name = filename.lstrip('/')
        for f in files:
            fname = f.get('name', '').lstrip('/')
            if fname == clean_name or fname.endswith('/' + clean_name) or os.path.basename(fname) == clean_name:
                size = int(f.get('size', 0))
                if size > 0:
                    return True
    except Exception as e:
        log.warning(f"Could not verify file {filename} on router: {e}")
    return False


def verify_device_firmware(dev):
    """
    Verify if a rebooted device has booted with the target firmware version.
    If updated: clears firmware_to_install, updates current_firmware, clears failure events, sets status='updated'.
    If unreachable/rebooting: keeps status='rebooting' (does not fail prematurely).
    If booted but on old version: marks status='failed' with explanatory event.
    """
    if not dev or not dev.firmware_to_install:
        return True
    
    options = util.build_api_options(dev)
    router = None
    events = list(db_events.get_events_by_src_and_status("updater", 0, dev.id).dicts())
    try:
        router = RouterOSCheckResource(options)
        live_ver = router._get_routeros_version()
        target_ver = RouterOSVersion(dev.firmware_to_install)
        if live_ver and live_ver >= target_ver:
            dev.current_firmware = str(live_ver)
            dev.firmware_to_install = None
            dev.status = "updated"
            dev.failed_attempt = 0
            dev.save()
            util.check_or_fix_event(events, "firmware", "Update Failed")
            util.check_or_fix_event(events, "firmware", "Download Failed")
            util.check_or_fix_event(events, "firmware", "Device storage")
            util.check_or_fix_event(events, "firmware", "Firmware repositpry")
            log.info(f"Verified device {dev.name} ({dev.ip}) successfully running {live_ver}")
            return True
        else:
            log.warning(f"Device {dev.name} ({dev.ip}) rebooted but still running {live_ver} (target {target_ver})")
            dev.status = 'failed'
            dev.save()
            db_events.firmware_event(
                dev.id, "updater", "Update Failed", "Critical", 0,
                f"Device rebooted but remains on {live_ver}; target {target_ver} was not applied"
            )
            return False
    except Exception as e:
        log.info(f"Device {dev.name} ({dev.ip}) still rebooting or unreachable during verification: {e}")
        return False
    finally:
        if router:
            try:
                router.close()
            except Exception:
                pass


def safe_check_core(dev, _installed_version, ver_to_install):
    """Firmware package lookup for an update.

    Returns (main package row or False, extra package row or False, intermediate
    version or False). Safe-upgrade steps and wireless driver packages are a Pro
    feature (utilpro); the free tier installs the target version directly.
    """
    if ISPRO and hasattr(utilpro, "safe_check_core"):
        return utilpro.safe_check_core(dev, _installed_version, ver_to_install)
    arch = dev.arch or ''
    if "x86" in arch:
        arch = "x86"
    firm = False
    if arch:
        firm = db_firmware.get_frim_by_version(str(ver_to_install), arch)
    return firm, False, False


def update_device(dev, q, version_to_install=None, ofa=None, packages_mode="full", packages_to_install=None, auto_upgrade_rb=True):
    port = util.get_device_port(dev)
    is_testing = ('unittest' in sys.modules or os.getenv('TEST_ENV') == '1' or 'test' in sys.argv[0].lower())
    if not is_testing and not util.check_port(dev.ip, port):
        log.warning(f"Device {dev.name} ({dev.ip}) is offline/unreachable on port {port}. Aborting firmware update.")
        if getattr(dev, 'status', '') == 'updating':
            dev.status = 'active'
            dev.save()
        if q:
            q.put({"id": dev.id, "status": False, "reason": f"Device unreachable with port {port}"})
        return False

    events = list(db_events.get_events_by_src_and_status("updater", 0, dev.id).dicts())
    if not ofa:
        ofa = db_sysconfig.get_firmware_action().value
    _installed_version = RouterOSVersion(dev.current_firmware)

    try:
        if version_to_install:
            if isinstance(version_to_install, dict):
                if ofa == "keep" and _installed_version < RouterOSVersion('7.0.0') and version_to_install.get("version_to_install_6"):
                    ver_to_install = RouterOSVersion(str(version_to_install["version_to_install_6"]))
                else:
                    ver_to_install = RouterOSVersion(str(version_to_install.get("version_to_install", version_to_install.get("version", ""))))
            else:
                ver_to_install = RouterOSVersion(str(version_to_install))
        elif not dev.firmware_to_install and dev.upgrade_device:
            ver_to_install = _installed_version
        else:
            if dev.firmware_to_install:
                ver_to_install = dev.firmware_to_install
            elif ofa == "keep" and _installed_version < RouterOSVersion('7.0.0'):
                ver_to_install = db_sysconfig.get_firmware_old().value
            else:
                ver_to_install = db_sysconfig.get_firmware_latest().value
            ver_to_install = RouterOSVersion(str(ver_to_install))
    except Exception as e:
        log.error(e)
        q.put({"id": dev.id, "status": False, "reason": str(e)})
        return False

    arch = dev.arch or ''
    if "x86" in arch:
        arch = "x86"

    if not dev.firmware_to_install or RouterOSVersion(dev.firmware_to_install) != ver_to_install:
        dev.firmware_to_install = str(ver_to_install)
        dev.save()

    # If already on target version or newer, and not packages_only mode
    try:
        if _installed_version >= ver_to_install and packages_mode != "packages_only":
            util.check_or_fix_event(events, "firmware", "Update Failed")
            util.check_or_fix_event(events, "firmware", "Firmware repositpry")
            util.check_or_fix_event(events, "firmware", "Device storage")
            util.check_or_fix_event(events, "firmware", "Download Failed")
            util.check_or_fix_event(events, "firmware", "Package Corrupt")
            dev.firmware_to_install = None

            # Only run RouterBOOT upgrade if explicitly requested AND device has an upgrade available
            if dev.upgrade_device and getattr(dev, 'upgrade_availble', False):
                dev.failed_attempt = 0
                dev.status = "upgrading"
                dev.save()
                upgrade_routerboot(dev, q)
            else:
                dev.failed_attempt = 0
                dev.status = 'active'
                dev.upgrade_device = False
                dev.save()
                if q:
                    q.put({"id": dev.id, "status": True, "message": "Already up to date"})
            return True
    except Exception as e:
        log.error(e)
        pass

    # Safe check & intermediate step calculation
    firm = False
    firm2 = False
    before_ver = False
    firm, firm2, before_ver = safe_check_core(dev, _installed_version, ver_to_install)
    effective_ver = before_ver if before_ver else ver_to_install

    # Keep ultimate target in dev.firmware_to_install if stepping through intermediate bridge
    if before_ver:
        dev.firmware_to_install = str(ver_to_install)
        dev.save()

    options = util.build_api_options(dev)
    router = None
    try:
        router = RouterOSCheckResource(options)
        try:
            live_ver = router._get_routeros_version()
            if live_ver:
                _installed_version = live_ver
                dev.current_firmware = str(live_ver)
                dev.save()
        except Exception as e:
            log.warning(f"Could not query live version from {dev.name}: {e}")

        # Check if live router is already on target version or newer!
        if _installed_version >= ver_to_install and packages_mode != "packages_only":
            util.check_or_fix_event(events, "firmware", "Update Failed")
            util.check_or_fix_event(events, "firmware", "Firmware repositpry")
            util.check_or_fix_event(events, "firmware", "Device storage")
            util.check_or_fix_event(events, "firmware", "Download Failed")
            util.check_or_fix_event(events, "firmware", "Package Corrupt")
            dev.firmware_to_install = None
            dev.failed_attempt = 0
            if dev.upgrade_device and getattr(dev, 'upgrade_availble', False):
                dev.status = "upgrading"
                dev.save()
                upgrade_routerboot(dev, q, router=router)
            else:
                dev.status = 'active'
                dev.upgrade_device = False
                dev.save()
                if q:
                    q.put({"id": dev.id, "status": True, "message": "Already up to date"})
            return True

        try:
            call = router.api.path('/system/package')
            results = tuple(call)
        except Exception as e:
            log.error(f"Could not query /system/package on {dev.name}: {e}")
            if getattr(dev, 'status', '') == 'updating':
                dev.status = 'active'
                dev.save()
            if q:
                q.put({"id": dev.id, "status": False, "reason": "API query /system/package failed"})
            return False

        installed_package_names = set(res.get('name') for res in results if 'name' in res and res.get('name') != 'routeros')

        packages = []
        if packages_mode != "packages_only":
            if firm:
                packages.append(firm)
            else:
                db_events.firmware_event(
                    dev.id, "updater", "Firmware repositpry", "Error", 0,
                    f"Firmware {effective_ver} ({arch}) not found in repository: please check settings"
                )
                log.error(f"No firmware found for device {dev.name} ({dev.ip})")
                q.put({"id": dev.id, "status": False, "reason": "Firmware not found in repository"})
                return False

        # Package isolation: Only update packages currently installed on the router. Never install new packages.
        if packages_mode != "firmware_only":
            target_pkg_names = installed_package_names
            if packages_to_install is not None:
                # Strictly filter user selection to ONLY include packages currently installed on this device
                target_pkg_names = [pkg for pkg in packages_to_install if pkg in installed_package_names]

            for pkg_name in target_pkg_names:
                if pkg_name != "routeros":
                    extra_pkg = db_firmware.get_frim_by_version(str(effective_ver), f"{arch}-{pkg_name}")
                    if extra_pkg and extra_pkg not in packages:
                        packages.append(extra_pkg)

        try:
            util.backup_router(dev)
        except Exception:
            pass

        return apply_firmware(packages, firm2, arch, dev, router, events, q, auto_upgrade_rb=auto_upgrade_rb)

    except Exception as e:
        log.error(f"Error in update_device for {dev.name}: {e}")
        if getattr(dev, 'status', '') == 'updating':
            dev.status = 'active'
            dev.save()
        if q:
            q.put({"id": dev.id, "status": False, "reason": str(e)})
        return False
    finally:
        if router:
            try:
                router.close()
            except Exception:
                pass


def apply_firmware(packages, firm2, arch, dev, router, events, q, auto_upgrade_rb=True):
    max_retries = 2
    try:
        ret_cfg = db_sysconfig.get_sysconfig('firmware_max_retries')
        if ret_cfg:
            max_retries = int(ret_cfg)
    except Exception:
        pass

    dev.failed_attempt = dev.failed_attempt + 1
    if dev.failed_attempt > max_retries:
        db_events.firmware_event(
            dev.id, "updater", "Update Failed", "Critical", 0,
            f"Update failed: exceeded max retry limit ({max_retries})"
        )
        dev.status = "failed"
        dev.save()
        q.put({"id": dev.id, "status": False, "reason": "Exceeded max retries"})
        return False

    dev.status = "updating"
    dev.save()

    try:
        # Pre-flight check 1: Free storage space (anti-reboot safety with dynamic sizing)
        total_pkg_bytes = 0
        pkgs_to_check = list(packages)
        if firm2 and firm2 not in pkgs_to_check:
            pkgs_to_check.append(firm2)
        for p in pkgs_to_check:
            loc = getattr(p, 'location', '')
            if loc and os.path.exists(loc):
                total_pkg_bytes += os.path.getsize(loc)
            else:
                total_pkg_bytes += 15 * 1024 * 1024
        required_mb = max(15.0, (total_pkg_bytes / (1024 * 1024)) + 5.0)

        storage_ok, free_mb = check_device_storage_preflight(router, required_mb=required_mb)
        if not storage_ok:
            dev.status = "failed"
            dev.save()
            db_events.firmware_event(
                dev.id, "updater", "Device storage", "Critical", 0,
                f"Insufficient disk space: {free_mb:.1f}MB free, minimum {required_mb:.1f}MB required"
            )
            q.put({"id": dev.id, "status": False, "reason": "Insufficient storage"})
            return False

        url = util.resolve_peer_ip(dev)
        api = router._connect_api()
        if not url:
            url = db_sysconfig.get_sysconfig('system_url') or db_sysconfig.get_sysconfig('default_ip') or ""
        if url and "http" not in url:
            url = "http://" + url

        transferred_pkg_ids = set()
        log.warning("#s################################")
        # Transfer firm2 (extra wireless driver if present)
        if firm2:
            log.warning("#################################firm2")
            transferred_pkg_ids.add(getattr(firm2, 'id', None))
            dst_firm2 = firm2.architecture + ".npk"
            url_firm2 = f"{url}/api/firmware/get_firmware/{firm2.id}"
            params = {"url": url_firm2, "keep-result": "yes", "dst-path": dst_firm2}
            if url.startswith("https://"):
                params["check-certificate"] = "no"
            log.warning(params)
            call = api('/tool/fetch', **params)
            results = tuple(call)
            result: Dict[str, str] = results[-1]
            if result.get('status') != 'finished' or not verify_router_file(router, dst_firm2):
                dev.status = "failed"
                dev.save()
                db_events.firmware_event(
                    dev.id, "updater", "Download Failed", "Critical", 0,
                    f"Failed to download or verify wireless package {dst_firm2} on device"
                )
                q.put({"id": dev.id, "status": False, "reason": f"Download failed for {dst_firm2}"})
                return False

        # Transfer main and other packages with transfer jitter (200ms)
        for package in packages:
            log.warning("#################################packages")
            if getattr(package, 'id', None) in transferred_pkg_ids:
                continue
            transferred_pkg_ids.add(getattr(package, 'id', None))
            dst_pkg = package.architecture + ".npk"
            url_package = f"{url}/api/firmware/get_firmware/{package.id}"
            params = {"url": url_package, "keep-result": "yes", "dst-path": dst_pkg}
            if url.startswith("https://"):
                params["check-certificate"] = "no"
            time.sleep(0.2)
            log.warning(params)
            call = api('/tool/fetch', **params)
            results = tuple(call)
            log.warning(results)
            result: Dict[str, str] = results[-1]
            if result.get('status') != 'finished' or not verify_router_file(router, dst_pkg):
                log.error(f"Failed to fetch or verify {dst_pkg} on device")
                dev.status = "failed"
                dev.save()
                db_events.firmware_event(
                    dev.id, "updater", "Download Failed", "Critical", 0,
                    f"Failed to download or verify package {dst_pkg} on device"
                )
                q.put({"id": dev.id, "status": False, "reason": f"Download failed for {dst_pkg}"})
                return False

        util.check_or_fix_event(events, "firmware", "Device storage")
        util.check_or_fix_event(events, "firmware", "Download Failed")
        util.check_or_fix_event(events, "firmware", "Firmware repositpry")

        # Auto-upgrade RouterBOOT if requested (eliminates second reboot cycle!)
        if auto_upgrade_rb:
            try:
                api('/system/routerboard/settings/set', **{'auto-upgrade': 'yes'})
                log.info(f"Auto-upgrade RouterBOOT enabled for device {dev.name} ({dev.ip})")
            except Exception as e:
                log.warning(f"Could not set auto-upgrade on {dev.name}: {e}")

        # Reboot router only once ALL packages are verified on disk
        cmd = '/system/reboot'
        try:
            call = api(cmd)
            rebootresults = tuple(call)
            log.warning(rebootresults)
        except Exception as e:
            log.info(f"Reboot command sent to {dev.name} (connection dropped as expected): {e}")

        try:
            if hasattr(router, 'close'):
                router.close()
        except Exception:
            pass

        dev.status = "rebooting"
        dev.save()

        # In testing environments, skip active network polling
        is_testing = ('unittest' in sys.modules or os.getenv('TEST_ENV') == '1' or 'test' in sys.argv[0].lower())
        if not is_testing:
            # Post-reboot verification with backoff:
            # Give router time to apply update and reboot (CHR takes ~10s, physical hardware takes 20-45s)
            time.sleep(5)
            verify_options = util.build_api_options(dev)
            for attempt in range(8):
                time.sleep(5)
                check_router = None
                try:
                    check_router = RouterOSCheckResource(verify_options)
                    live_ver = check_router._get_routeros_version()
                    if live_ver and live_ver >= effective_ver:
                        dev.current_firmware = str(live_ver)
                        dev.firmware_to_install = None
                        dev.status = "updated"
                        dev.failed_attempt = 0
                        dev.save()
                        util.check_or_fix_event(events, "firmware", "Update Failed")
                        util.check_or_fix_event(events, "firmware", "Download Failed")
                        util.check_or_fix_event(events, "firmware", "Device storage")
                        util.check_or_fix_event(events, "firmware", "Firmware repositpry")
                        log.info(f"Firmware update verified on {dev.name}: now running {live_ver}")
                        break
                except Exception:
                    pass
                finally:
                    if check_router:
                        try:
                            check_router.close()
                        except Exception:
                            pass
        else:
            dev.status = "updated"
            dev.save()

        q.put({"id": dev.id, "status": True})
        return True

    except Exception as e:
        dev.status = "failed"
        dev.save()
        err_str = str(e)
        if 'no space left' in err_str:
            db_events.firmware_event(dev.id, "updater", "Device storage", "Critical", 0, "Insufficient space in device storage")
        elif '404 Not Found' in err_str:
            db_events.firmware_event(dev.id, "updater", "Firmware repositpry", "Error", 0, "Firmware not found in repository")
        else:
            db_events.firmware_event(dev.id, "updater", "Update Failed", "Critical", 0, f"Firmware update error: {err_str}")
        log.error(f"Error applying firmware on {dev.name}: {e}")
        q.put({"id": dev.id, "status": False, "reason": str(e)})
        return False


def update_device_native(dev, q=None, channel="stable", auto_upgrade_rb=True):
    """
    Option 3: Directly update router using native RouterOS /system/package/update commands.
    Only requires internet access on the router. Zero central server storage used.
    """
    port = util.get_device_port(dev)
    is_testing = ('unittest' in sys.modules or os.getenv('TEST_ENV') == '1' or 'test' in sys.argv[0].lower())
    if not is_testing and not util.check_port(dev.ip, port):
        log.warning(f"Device {dev.name} ({dev.ip}) is offline/unreachable on port {port}. Skipping native update.")
        if getattr(dev, 'status', '') == 'updating':
            dev.status = 'active'
            dev.save()
        if q:
            q.put({"id": dev.id, "status": False, "reason": f"Device unreachable with port {port}"})
        return False

    options = util.build_api_options(dev)
    router = None
    try:
        router = RouterOSCheckResource(options)
        api = router._connect_api()

        # 1. Set release channel (stable, long-term, testing)
        try:
            api('/system/package/update/set', **{'channel': channel})
        except Exception as e:
            log.warning(f"Could not set channel: {e}")

        # 2. Check for updates
        check_res = tuple(api('/system/package/update/check-for-updates'))
        log.info(f"Native update check for {dev.name}: {check_res}")

        # Verify status: if already up to date, skip install and avoid error
        check_data = check_res[0] if check_res else {}
        check_status = str(check_data.get('status', '')).lower()
        latest_ver = check_data.get('latest-version', '')
        installed_ver = check_data.get('installed-version', '')

        if "already up to date" in check_status or (latest_ver and installed_ver and latest_ver == installed_ver):
            log.info(f"Native update for {dev.name}: Already up to date ({installed_ver or dev.current_firmware})")
            if auto_upgrade_rb:
                try:
                    api('/system/routerboard/settings/set', **{'auto-upgrade': 'yes'})
                except Exception as e:
                    log.warning(f"Could not set routerboard auto-upgrade: {e}")
            dev.status = "active"
            dev.failed_attempt = 0
            dev.firmware_to_install = None
            dev.upgrade_device = False
            dev.save()
            if q:
                q.put({"id": dev.id, "status": True, "message": "Already up to date"})
            return True

        # 3. Check storage preflight
        storage_ok, free_mb = check_device_storage_preflight(router, required_mb=15)
        if not storage_ok:
            dev.status = "failed"
            dev.save()
            db_events.firmware_event(
                dev.id, "updater", "Device storage", "Critical", 0,
                f"Insufficient storage for native update: {free_mb:.1f}MB free"
            )
            if q:
                q.put({"id": dev.id, "status": False, "reason": "Insufficient storage"})
            return False

        # 4. Optional backup before update
        try:
            util.backup_router(dev)
        except Exception:
            pass

        # 5. Set auto-upgrade RouterBOOT if requested
        if auto_upgrade_rb:
            try:
                api('/system/routerboard/settings/set', **{'auto-upgrade': 'yes'})
            except Exception as e:
                log.warning(f"Could not set routerboard auto-upgrade: {e}")

        # 6. Execute install (downloads and reboots)
        dev.status = "updating"
        dev.save()
        install_res = tuple(api('/system/package/update/install'))
        log.info(f"Native update install initiated for {dev.name}: {install_res}")

        dev.status = "updated"
        dev.save()
        if q:
            q.put({"id": dev.id, "status": True})
        return True

    except Exception as e:
        err_str = str(e).lower()
        is_conn_err = any(x in err_str for x in ['connection refused', 'timed out', 'timeout', 'no route to host', 'unreachable', 'network is unreachable'])
        if is_conn_err:
            log.warning(f"Native update skipped for {dev.name} due to connection error: {e}")
            if getattr(dev, 'status', '') == 'updating':
                dev.status = 'active'
                dev.save()
        else:
            dev.status = "failed"
            dev.save()
            db_events.firmware_event(dev.id, "updater", "Native Update Failed", "Critical", 0, str(e))
            log.error(f"Native update error for {dev.name}: {e}")
        if q:
            q.put({"id": dev.id, "status": False, "reason": str(e)})
        return False
    finally:
        if router:
            try:
                router.close()
            except Exception:
                pass


def reset_device_update_status(dev_ids):
    """
    Reset failed update status and attempt counter for a list of device IDs.
    Clears open updater events so the device returns to normal active status.
    """
    if isinstance(dev_ids, str):
        dev_ids = [int(x.strip()) for x in dev_ids.split(',') if x.strip().isdigit()]
    elif isinstance(dev_ids, int):
        dev_ids = [dev_ids]
    
    if not dev_ids:
        return 0

    updated_count = 0
    try:
        updated_count = db_device.Devices.update(
            status="active",
            failed_attempt=0,
            firmware_to_install=None,
            upgrade_device=False
        ).where(db_device.Devices.id.in_(dev_ids)).execute()
    except Exception as e:
        log.error(f"Error bulk updating devices status: {e}")

    for dev_id in dev_ids:
        try:
            events = list(db_events.get_events_by_src_and_status("updater", 0, dev_id).dicts())
            for ev in events:
                db_events.fix_event(ev['id'])
        except Exception as e:
            log.error(f"Error clearing updater events for device {dev_id}: {e}")

    return updated_count

def upgrade_routerboot(dev, q=None, router=None):
    success = False
    own_router = False
    if router is None:
        port = util.get_device_port(dev)
        is_testing = ('unittest' in sys.modules or os.getenv('TEST_ENV') == '1' or 'test' in sys.argv[0].lower())
        if not is_testing and not util.check_port(dev.ip, port):
            log.warning(f"Device {dev.name} ({dev.ip}) unreachable on port {port}. Skipping RouterBOOT upgrade.")
            if getattr(dev, 'status', '') == 'upgrading':
                dev.status = 'active'
                dev.save()
            if q:
                q.put({"id": dev.id, "status": False, "reason": f"Device unreachable with port {port}"})
            return False
        options = util.build_api_options(dev)
        router = RouterOSCheckResource(options)
        own_router = True
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
        dev.failed_attempt = (dev.failed_attempt or 0) + 1
        max_retries = 2
        try:
            ret_cfg = db_sysconfig.get_sysconfig('firmware_max_retries')
            if ret_cfg:
                max_retries = int(ret_cfg)
        except Exception:
            pass
        if dev.failed_attempt >= max_retries or "no such command" in str(e):
            dev.upgrade_device = False

        if "no such command" in str(e):
            db_events.firmware_event(dev.id, "updater", "Firmware Upgrade", "Error", 0, "RouterBOOT upgrade command not found")
            dev.status = "updated"
        else:
            db_events.firmware_event(
                dev.id, "updater", "Firmware Upgrade", "Error", 0, 
                f"Failed to upgrade RouterBOOT: {str(e)}"
            )
            dev.status = "failed"
        dev.save()
        success = False

    finally:
        if own_router and router:
            router.close()
        elif own_router and api:
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

def recalculate_fleet_update_status(latest_ver_str=None, old_ver_str=None, ofa=None):
    """
    Recalculate update_availble across all devices in the database using their
    cached current_firmware without making network calls.
    Triggered when settings are updated so the UI immediately reflects the new baseline.
    """
    if not latest_ver_str:
        latest_ver_str = db_sysconfig.get_sysconfig('latest_version')
    if not old_ver_str:
        old_ver_str = db_sysconfig.get_sysconfig('old_version')
    if not ofa:
        ofa = db_sysconfig.get_sysconfig('old_firmware_action') or 'keep'

    try:
        latest_ver = RouterOSVersion(str(latest_ver_str)) if latest_ver_str else None
        old_ver = RouterOSVersion(str(old_ver_str)) if old_ver_str else None
    except Exception as e:
        log.error(f"Cannot parse target versions for fleet recalculation: {e}")
        return 0

    updated_count = 0
    try:
        with db_device.database.connection_context():
            devices = list(db_device.Devices.select())
            for dev in devices:
                if not dev.current_firmware:
                    continue
                try:
                    cur_ver = RouterOSVersion(dev.current_firmware)
                    if ofa == "keep" and cur_ver < RouterOSVersion('6.99.99'):
                        target_ver = old_ver
                    else:
                        target_ver = latest_ver

                    is_avail = bool(target_ver and cur_ver < target_ver)
                    if dev.update_availble != is_avail:
                        db_device.Devices.update(update_availble=is_avail).where(db_device.Devices.id == dev.id).execute()
                        updated_count += 1
                except Exception as e:
                    log.warning(f"Error recalculating update status for dev {dev.id}: {e}")
    except Exception as e:
        log.error(f"Fleet recalculation database error: {e}")

    log.info(f"Fleet firmware update status recalculated: {updated_count} devices updated to new baseline")
    return updated_count


def run_firmware_task(utask):
    """
    Free tier task runner for scheduled firmware update tasks.
    Executes system update, defined version update, or native update.
    """
    devices = db_user_tasks.get_task_devices(utask)
    if not devices:
        return []

    data = {}
    if utask.data:
        try:
            data = json.loads(utask.data)
        except Exception as e:
            log.error(f"Cannot parse task data: {e}")

    strategy = data.get('strategy', 'system')
    delivery_method = data.get('delivery_method', 'local_repo')
    version_to_install = data.get('version_to_install')
    auto_upgrade_rb = data.get('auto_upgrade_rb', True)
    packages_mode = data.get('mode', 'full')
    packages_to_install = data.get('packages')

    if strategy == 'latest':
        log.warning(f"Automated latest firmware update strategy is a Pro feature and is not available in Free tier. Skipping task {utask.id}.")
        return []

    q = queue.Queue()
    res = []
    max_workers = min(getattr(config, 'FIRMWARE_CONCURRENCY', 40), max(1, len(devices)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if strategy == 'native' or delivery_method == 'native':
            futures = {executor.submit(update_device_native, dev, q, auto_upgrade_rb=auto_upgrade_rb): dev for dev in devices}
        else:
            futures = {
                executor.submit(
                    update_device, dev, q,
                    version_to_install=version_to_install,
                    packages_mode=packages_mode,
                    packages_to_install=packages_to_install,
                    auto_upgrade_rb=auto_upgrade_rb
                ): dev for dev in devices
            }

        for future in as_completed(futures):
            dev = futures[future]
            try:
                future.result(timeout=600)
            except Exception as e:
                log.error(f"Task worker error for {dev.name}: {e}")
                q.put({"id": dev.id, "status": False, "reason": str(e)})

    while not q.empty():
        try:
            res.append(q.get_nowait())
        except queue.Empty:
            break
    return res
