#!/usr/bin/python
# -*- coding: utf-8 -*-

# firm_lib.py: RouterOS firmware repository and update engine
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com
#
# Update flow (one device, under a per-device lease - see libs/fw_state.py):
#   1. read the router: version, architecture, packages, files, free space, uptime
#   2. plan: final target (settings / request, "keep v6" policy), next step and the exact
#      package set (free rules: libs/fw_plan.py, Pro rules: libs/fw_plan_pro.py)
#   3. make sure every package is in the repository (verified against MikroTik's .sha256)
#   4. pre-checks on the router: no foreign .npk files, enough free space
#   5. router downloads every package (/tool/fetch), size checked against the repository
#   6. reboot; the firmware mule verifies the result (libs/firm_lib.verify_device_firmware)
#      and continues with the next step of a multi-step upgrade
# Anything that fails before the reboot removes the uploaded packages again, so a later
# (unplanned) reboot never installs a partial package set.

import sys
import datetime
import time
import socket
import config
import fcntl
import threading
from libs.db import db_sysconfig, db_firmware, db_tasks, db_events, db_device, db_user_tasks
from libs.db.db import database
from libs.check_routeros.routeros_check.resource import RouterOSCheckResource
from libs.check_routeros.routeros_check.helper import RouterOSVersion
from libs import fw_plan, fw_state, job_control
from libs.fw_plan import PlanError
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
from typing import Dict
import re
import json
import logging
import os
import uuid
from bs4 import BeautifulSoup
import hashlib
from librouteros.exceptions import TrapError, MultiTrapError, FatalError, ConnectionClosed
log = logging.getLogger("util")
from libs import util
from libs.ssh_helper import SSH_Helper
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass
try:
    from libs import fw_plan_pro
except ImportError:
    fw_plan_pro = None


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

# Repository architectures (MikroTik download names; v6 PowerPC files use "powerpc")
ARCHES = list(fw_plan.ARCHES)
DOWNLOAD_BASES = ("https://download.mikrotik.com/routeros/", "https://cdn.mikrotik.com/routeros/")

# Error replies from the router. Unknown commands come as TWO traps ("no such command or
# directory (x)", "no such command prefix") which librouteros raises as MultiTrapError -
# not a TrapError subclass.
RouterTrap = (TrapError, MultiTrapError)

API_TIMEOUT = 10            # seconds, normal API calls during an update
TRANSFER_API_TIMEOUT = 120  # seconds without a reply from /tool/fetch before giving up
FREE_SPACE_MARGIN = 1024 * 1024
FILE_APPEAR_TIMEOUT = 20    # seconds a fetched file may take to be listed in /file with its full size
FILE_APPEAR_POLL = 1.0
REBOOT_MIN_WAIT = 20        # seconds after the reboot command before verifying
REBOOT_NOT_STARTED = 300    # router still up (uptime not reset) this long after the command
RETRY_BACKOFF = 300         # seconds between automatic retries of a failed device
UNREACHABLE_BACKOFF = 120   # queued device offline: try again after
MAX_RECOVERIES = 3          # times a job interrupted by a process restart is restarted

_transfer_slots = threading.BoundedSemaphore(max(1, int(getattr(config, "FIRMWARE_MAX_TRANSFERS", 3))))


# ---------------------------------------------------------------------------
# MikroTik download server
# ---------------------------------------------------------------------------

def _http_head(url, timeout=10):
    return requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)


def _http_get(url, timeout=30, stream=False):
    return requests.get(url, headers=HEADERS, timeout=timeout, stream=stream)


def package_urls(file_name, version):
    """Download URLs of a file, main server first, then the CDN."""
    vs = fw_plan.vstr(version)
    return [base + vs + "/" + file_name for base in DOWNLOAD_BASES]


def official_sha256(url, timeout=15):
    """sha256 MikroTik publishes next to every file ('<file>.sha256').
    Returns the hex digest, None when the server has no checksum file (404), and raises
    on network errors (the caller must not treat 'unknown' as 'verified')."""
    r = _http_get(url + ".sha256", timeout=timeout)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return fw_plan.parse_sha256_file(r.text, url.rsplit("/", 1)[-1])


def extract_from_link(link, all_package=False):
    """Kept for compatibility: version/arch from a MikroTik download link (v6 and v7)."""
    try:
        name = link.rsplit("/", 1)[-1]
        version = link.split("/")[-2]
        if all_package:
            m = re.match(r"all_packages-([a-z0-9]+)-.+\.zip$", name)
            if not m:
                return False
            return {"link": link, "arch": m.group(1), "version": version, "all_package": True}
        for arch in ARCHES:
            if name == fw_plan.main_package_filename(version, arch):
                return {"link": link, "arch": arch, "version": version}
        return False
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
    """{version: {arch: {"link", "sha"}, "<arch>-allpackage": {...}}} for files that exist."""
    try:
        vs = fw_plan.vstr(version)
        result = {}
        for arch in ARCHES:
            names = [(arch, fw_plan.main_package_filename(vs, arch))]
            if all_package:
                names.append((arch + "-allpackage", fw_plan.all_packages_filename(vs, arch)))
            for key, file_name in names:
                for url in package_urls(file_name, vs):
                    try:
                        if _http_head(url).status_code == 200:
                            result.setdefault(vs, {})[key] = {"link": url, "sha": None}
                            break
                    except requests.RequestException:
                        continue
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



_sha_cache = {}
_sha_cache_lock = threading.Lock()


def file_sha256(path):
    """sha256 of a file, read in chunks; cached by (path, size, mtime)."""
    st = os.stat(path)
    key = (path, st.st_size, st.st_mtime_ns)
    with _sha_cache_lock:
        hit = _sha_cache.get(key)
    if hit:
        return hit
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    with _sha_cache_lock:
        if len(_sha_cache) > 4096:
            _sha_cache.clear()
        _sha_cache[key] = digest
    return digest


def check_sha256(path, sha256=False):
    """sha256 of the file (sha256=False) or whether it matches sha256. False if missing."""
    if not path or not os.path.exists(path):
        return False
    digest = file_sha256(path)
    if not sha256:
        return digest
    return digest == sha256


def _is_npk(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) in (b'hsqs', b'sqsh', b'\xba\xd0\xf1\x1e', b'\x1e\xf1\xd0\xba')
    except Exception:
        return False


def _tmp_path(final_path):
    return "{}.{}.{}.tmp".format(final_path, os.getpid(), uuid.uuid4().hex[:8])


class _FileLock(object):
    """Exclusive lock (between threads and processes) for one repository file."""

    def __init__(self, path):
        self.path = path
        self.fd = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
        return False


def web2file(url, filePath, sha256=False, tries=3, timeout=30, sleepBetween=2, strict_sha=False, min_npk_size=100000):
    """Download url to filePath (atomic: unique temp file + os.replace).

    Checks: Content-Length, NPK magic / ZIP CRC, and sha256. With strict_sha=True the
    download only succeeds when the file matches `sha256` (MikroTik's published checksum).
    Returns True/False.
    """
    if os.path.exists(filePath) and sha256 and check_sha256(filePath, sha256):
        log.info(f"File already exists with correct SHA256: {filePath}")
        return True
    if strict_sha and not sha256:
        log.error(f"Refusing download of {url}: no checksum to verify against")
        return False

    for attempt in range(tries):
        tempPath = _tmp_path(filePath)
        try:
            log.info(f"Downloading {url} (attempt {attempt + 1}/{tries})")
            response = _http_get(url, timeout=timeout, stream=True)
            response.raise_for_status()
            expected_size = int(response.headers.get('Content-Length', 0) or 0)
            downloaded_size = 0
            hash_obj = hashlib.sha256()
            with open(tempPath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        hash_obj.update(chunk)
                        downloaded_size += len(chunk)
            if expected_size and downloaded_size != expected_size:
                raise IOError(f"size mismatch: server {expected_size}, downloaded {downloaded_size}")
            if downloaded_size == 0:
                raise IOError("empty download")
            if filePath.endswith('.npk'):
                if not _is_npk(tempPath):
                    raise IOError("not a RouterOS package (bad NPK header)")
                if not strict_sha and downloaded_size < min_npk_size and not verify_npk_structure(tempPath):
                    raise IOError("NPK structure check failed")
            elif filePath.endswith('.zip'):
                if not verify_zip_structure(tempPath):
                    raise IOError("ZIP structure check failed")
            calculated = hash_obj.hexdigest()
            if sha256 and calculated != sha256:
                if strict_sha:
                    raise IOError(f"SHA256 mismatch: expected {sha256}, got {calculated}")
                log.warning(f"SHA256 differs from stored value for {filePath} (file updated on server?)")
            os.replace(tempPath, filePath)
            log.info(f"Download verified and saved to {filePath} ({downloaded_size} bytes, sha256 {calculated})")
            return True
        except Exception as e:
            log.error(f"Download of {url} failed: {e}")
            if attempt < tries - 1:
                time.sleep(sleepBetween)
        finally:
            if os.path.exists(tempPath):
                try:
                    os.remove(tempPath)
                except OSError:
                    pass
    return False


def extract_zip(file, path):
    """Extract the .npk members of a zip into path (file names only, atomic writes).
    Returns the extracted member names."""
    names = []
    try:
        with zipfile.ZipFile(file, 'r') as zip_ref:
            for info in zip_ref.infolist():
                base = os.path.basename(info.filename.replace("\\", "/"))
                if not base or not base.endswith(".npk"):
                    continue
                dest = os.path.join(path, base)
                tmp = _tmp_path(dest)
                try:
                    with zip_ref.open(info) as src, open(tmp, "wb") as out:
                        for chunk in iter(lambda: src.read(1024 * 1024), b""):
                            out.write(chunk)
                    os.replace(tmp, dest)
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                names.append(base)
    except Exception as e:
        log.error(f"Could not extract {file}: {e}")
        return []
    return names


def _repo_dir(version):
    return os.path.join(config.FIRM_DIR, fw_plan.vstr(version))


def _db_get_firm(version, key):
    with database.connection_context():
        return db_firmware.get_frim_by_version(fw_plan.vstr(version), key)


def _db_upsert_firm(version, key, location, sha):
    vs = fw_plan.vstr(version)
    with database.connection_context():
        db_firmware.Firmware.insert(version=vs, location=location, architecture=key, sha256=sha).on_conflict(
            conflict_target=['version', 'architecture'],
            update={'sha256': sha, 'location': location}).execute()
        return db_firmware.get_frim_by_version(vs, key)


_VERIFIED_KEY = "mw:fw:sha_ok:{}"


def _remember_official_ok(sha):
    try:
        fw_state._redis().set(_VERIFIED_KEY.format(sha), "1", ex=30 * 24 * 3600)
    except Exception:
        pass


_UNREACHABLE_KEY = "mw:fw:sha_unreachable:{}"


def _remember_official_unreachable(sha):
    try:
        fw_state._redis().set(_UNREACHABLE_KEY.format(sha), "1", ex=3600)
    except Exception:
        pass


def _official_unreachable_recently(sha):
    try:
        return bool(fw_state._redis().exists(_UNREACHABLE_KEY.format(sha)))
    except Exception:
        return False


def _official_ok_known(sha):
    try:
        return bool(fw_state._redis().exists(_VERIFIED_KEY.format(sha)))
    except Exception:
        return False


def _repo_file_ok(row, official_name=None, version=None):
    """True when a repository row points to an intact package file. When the file was not
    yet checked against MikroTik's published sha256 (older downloads) it is checked once;
    a mismatch means the file is replaced."""
    try:
        if not row or not row.location or not os.path.isfile(row.location):
            return False
        if os.path.getsize(row.location) <= 0 or not _is_npk(row.location):
            return False
        local = file_sha256(row.location)
        if row.sha256 and local != row.sha256:
            log.error(f"Repository file {row.location} changed on disk (sha256 mismatch)")
            return False
        if official_name and version and not _official_ok_known(local) and not _official_unreachable_recently(local):
            unreachable = True
            for url in package_urls(official_name, version):
                try:
                    official = official_sha256(url, timeout=5)
                    unreachable = False
                except Exception:
                    continue          # MikroTik unreachable: keep using the local copy
                if official is None:
                    break
                if official != local:
                    log.error(f"Repository file {row.location} does not match MikroTik's sha256")
                    return False
                _remember_official_ok(local)
                break
            if unreachable:
                _remember_official_unreachable(local)
        return True
    except Exception as e:
        log.warning(f"Repository check of {getattr(row, 'location', '?')} failed: {e}")
        return False


def _download_official(file_name, version, dest):
    """Download one MikroTik file into dest, verified against its .sha256 when MikroTik
    publishes one. Returns the sha256 or None."""
    for url in package_urls(file_name, version):
        try:
            official = official_sha256(url)
        except Exception as e:
            log.warning(f"Checksum of {url} not available: {e}")
            continue
        if official is None:
            # No checksum published (very old releases): fall back to the structural checks
            try:
                if _http_head(url).status_code != 200:
                    continue
            except requests.RequestException:
                continue
            log.warning(f"MikroTik publishes no sha256 for {url}; using structural checks only")
            if web2file(url, dest):
                return file_sha256(dest)
            continue
        if web2file(url, dest, sha256=official, strict_sha=True):
            _remember_official_ok(official)
            return official
    return None


def _ensure_zip(version, arch):
    """Download and extract all_packages-<arch>-<ver>.zip; registers every package."""
    vs = fw_plan.vstr(version)
    folder = _repo_dir(vs)
    zip_name = fw_plan.all_packages_filename(vs, arch)
    dest = os.path.join(folder, "all_packages-{}.zip".format(arch))
    if not _download_official(zip_name, vs, dest):
        return []
    rows = []
    for member in extract_zip(dest, folder):
        pkg = fw_plan.package_name_from_zip_member(member, vs)
        if not pkg or pkg == "routeros" or pkg.startswith("routeros-"):
            continue
        location = os.path.join(folder, member)
        if not _is_npk(location):
            continue
        rows.append(_db_upsert_firm(vs, fw_plan.repo_architecture_key(arch, pkg), location, file_sha256(location)))
    return rows


def ensure_firmware(version, arch, pkg=None):
    """Repository row for the main package (pkg=None) or an extra package of a version and
    architecture, downloading it from MikroTik when missing or damaged. Safe to call from
    many threads/processes at once (one download per file). Raises PlanError."""
    vs = fw_plan.vstr(version)
    if arch not in ARCHES:
        raise PlanError("unknown_arch", f"Unknown architecture '{arch}'", event="Firmware repositpry")
    key = fw_plan.repo_architecture_key(arch, pkg)
    v7 = fw_plan.ver(vs).major >= 7
    if pkg is None:
        official_name = fw_plan.main_package_filename(vs, arch)
    elif v7:
        official_name = fw_plan.extra_package_filename(pkg, vs, arch)
    else:
        official_name = None            # v6 extra packages only exist inside the zip
    folder = _repo_dir(vs)
    with _FileLock(os.path.join(folder, ".{}.lock".format(key))):
        row = _db_get_firm(vs, key)
        if _repo_file_ok(row, official_name, vs):
            return row
        sha = None
        if official_name:
            dest = os.path.join(folder, key + ".npk") if pkg is None else os.path.join(folder, official_name)
            sha = _download_official(official_name, vs, dest)
            if sha:
                return _db_upsert_firm(vs, key, dest, sha)
        if pkg is not None:
            with _FileLock(os.path.join(folder, ".all_packages-{}.lock".format(arch))):
                _ensure_zip(vs, arch)
            row = _db_get_firm(vs, key)
            if _repo_file_ok(row):
                return row
    what = "RouterOS {} ({})".format(vs, arch) if pkg is None else "package '{}' {} ({})".format(pkg, vs, arch)
    raise PlanError("package_missing", f"{what} is not in the repository and could not be downloaded",
                    permanent=False, event="Firmware repositpry", severity="Error")


def download_firmware_to_repository(version, q, arch="all", all_package=True):
    """Repository download requested from the UI (main package of every / one architecture,
    plus all extra packages when all_package). Always reports one result to q."""
    ok = False
    try:
        vs = fw_plan.vstr(version)
        arches = ARCHES if arch in (None, "", "all") else [fw_plan.canonical_arch(arch)]
        for a in arches:
            if not a:
                continue
            task = db_tasks.downloader_job_status()
            if task.action == "cancel":
                log.info("Firmware Download Task Canceled")
                break
            try:
                ensure_firmware(vs, a)
                ok = True
            except PlanError as e:
                log.info(f"{e.message}")
            if all_package:
                with _FileLock(os.path.join(_repo_dir(vs), ".all_packages-{}.lock".format(a))):
                    if _ensure_zip(vs, a):
                        ok = True
    except Exception as e:
        log.error(f"download_firmware_to_repository({version}, {arch}) failed: {e}")
        ok = False
    if q:
        q.put({"status": ok})
    return ok


# ---------------------------------------------------------------------------
# Router access
# ---------------------------------------------------------------------------

def _no_such_command(exc):
    return "no such command" in str(exc).lower()


def _connect(dev, timeout=API_TIMEOUT):
    """(RouterOSCheckResource, Api) - connects immediately, raises on failure."""
    with database.connection_context():
        options = util.build_api_options(dev)
    options["timeout"] = timeout
    router = RouterOSCheckResource(options)
    try:
        api = router._connect_api()
    except Exception:
        _close(router)
        raise
    return router, api


def _close(router):
    if router is not None:
        try:
            router.close()
        except Exception:
            pass


def _call(api, cmd, **params):
    """Run a command and read the whole reply (librouteros only sends a command when its
    reply is read - never call api(...) without consuming it)."""
    return list(api(cmd, **params))


def _print(api, path, **params):
    return _call(api, path.rstrip("/") + "/print", **params)


def _read_state(api):
    res = _print(api, "/system/resource")
    res = res[0] if res else {}
    rows = _print(api, "/system/package")
    files = _print(api, "/file")
    rb = {}
    try:
        rb_rows = _print(api, "/system/routerboard")
        rb = rb_rows[0] if rb_rows else {}
    except RouterTrap as e:
        if not _no_such_command(e):
            raise
    version = str(res.get("version") or "").partition(" ")[0] or fw_plan.main_package_version(rows)
    return {
        "version": version,
        "arch": fw_plan.canonical_arch(res.get("architecture-name")),
        "arch_name": res.get("architecture-name"),
        "free": res.get("free-hdd-space"),
        "uptime": fw_plan.parse_uptime(res.get("uptime")),
        "board": res.get("board-name") or "",
        "rows": rows,
        "files": files,
        "rb": rb,
    }


def _print_optional(api, path):
    """Rows of a menu; [] when the menu does not exist on this router."""
    try:
        return _print(api, path)
    except RouterTrap as e:
        if _no_such_command(e):
            return []
        raise


def _remove_files(api, rows):
    """Remove files from the router; returns names that could not be removed."""
    failed = []
    for row in rows:
        try:
            _call(api, "/file/remove", **{".id": row[".id"]})
        except Exception as e:
            log.warning(f"Could not remove {row.get('name')} from router: {e}")
            failed.append(row.get("name"))
    return failed


def _cleanup_own_files(dev, api=None):
    """Remove MikroWizard package files from the router (they would be installed by the next
    reboot). Opens its own connection when api is None. Returns True when the router has no
    own package file left."""
    router = None
    try:
        if api is None:
            router, api = _connect(dev)
        own, _foreign = fw_plan.classify_device_files(_print(api, "/file"))
        if not own:
            return True
        return not _remove_files(api, own)
    except Exception as e:
        log.error(f"Cleanup of uploaded packages on {dev.name} ({dev.ip}) failed: {e}")
        return False
    finally:
        _close(router)


def _firmware_backup(dev, api):
    """Configuration export over SSH before an update (stored like a normal backup).
    SSH is enabled for the export when it is disabled and always disabled again.
    No DB connection is held during the SSH session. Returns True when stored."""
    ssh_row = None
    was_disabled = False
    try:
        services = _print(api, "/ip/service")
        ssh_row = next((s for s in services if s.get("name") == "ssh"), None)
        if ssh_row is None:
            log.warning(f"Backup before update of {dev.name}: no ssh service on the router")
            return False
        was_disabled = fw_plan._truthy(ssh_row.get("disabled"))
        if was_disabled:
            _call(api, "/ip/service/set", **{".id": ssh_row[".id"], "disabled": "no"})
        with database.connection_context():
            options = util.build_api_options(dev)
        options["ssh_port"] = ssh_row.get("port", 22)
        options["router"] = _ApiRouter(api)
        configs = SSH_Helper(options).get_config()
        if not configs:
            return False
        with database.connection_context():
            return bool(util.store_config(dev, configs))
    except Exception as e:
        log.warning(f"Backup before update of {dev.name} ({dev.ip}) failed: {e}")
        return False
    finally:
        if was_disabled and ssh_row is not None:
            try:
                _call(api, "/ip/service/set", **{".id": ssh_row[".id"], "disabled": "yes"})
            except Exception as e:
                log.error(f"SSH service of {dev.name} ({dev.ip}) could not be disabled again after the backup: {e}")
                _event(dev.id, "Update Failed", "Warning",
                       "SSH service was enabled for the pre-update backup and could not be disabled again")


class _ApiRouter(object):
    """Minimal RouterOSCheckResource stand-in for SSH_Helper (it only reads the version)."""

    def __init__(self, api):
        self.api = api


def _server_url(dev):
    url = util.resolve_peer_ip(dev)
    if not url:
        with database.connection_context():
            url = db_sysconfig.get_sysconfig('system_url') or db_sysconfig.get_sysconfig('default_ip') or ""
    url = (url or "").strip().rstrip("/")
    if url and not url.startswith("http"):
        url = "http://" + url
    return url


def _describe_files(rows, limit=12):
    """Short text of the package / MikroWizard files on the router (for error messages)."""
    shown = []
    for r in rows or ():
        name = str(r.get("name") or "")
        if fw_plan.is_package_file(r) or fw_plan.is_own_file(fw_plan._base_name(name)):
            shown.append("{} ({} bytes)".format(name, r.get("size")))
    if not shown:
        return "no package files"
    more = len(shown) - limit
    return ", ".join(shown[:limit]) + (" and {} more".format(more) if more > 0 else "")


def _wait_for_file(api, dst_name, expected, timeout=None, poll=None):
    """RouterOS can report a fetch as finished a moment before /file lists the file (or
    lists it with its final size). Polls /file until the file is there with the expected
    size, its size stops changing (wrong size: reported by the caller) or the timeout
    passes. Returns (row or None, last /file rows)."""
    timeout = FILE_APPEAR_TIMEOUT if timeout is None else timeout
    poll = FILE_APPEAR_POLL if poll is None else poll
    deadline = time.monotonic() + max(0, timeout)
    last_size = None
    while True:
        rows = _print(api, "/file")
        row = fw_plan.find_file(rows, dst_name)
        size = None
        if row is not None:
            try:
                size = int(row.get("size"))
            except (TypeError, ValueError):
                return row, rows          # unexpected value: reported by the caller
            if size == expected or (last_size is not None and size == last_size):
                return row, rows
        if time.monotonic() >= deadline:
            return row, rows
        last_size = size
        time.sleep(poll)


def _fetch_to_router(api, dev, firm, dst_name, server_url, step=None, arch=None, router_major=7):
    """Router downloads one package from this server. The file size must equal the
    repository file and the router must read it as the expected package (name, version,
    architecture - RouterOS parses the package header in /file). Raises RuntimeError."""
    expected = os.path.getsize(firm.location)
    url = "{}/api/firmware/get_firmware/{}".format(server_url, firm.id)
    params = {"url": url, "dst-path": dst_name, "keep-result": "yes"}
    if server_url.startswith("https://"):
        params["check-certificate"] = "no"
    with _transfer_slots:
        replies = _call(api, "/tool/fetch", **params)
    statuses = [r.get("status") for r in replies if r.get("status")]
    if not statuses or statuses[-1] != "finished":
        raise RuntimeError("download of {} did not finish ({})".format(dst_name, statuses[-1] if statuses else "no status"))
    last = replies[-1] if replies else {}
    row, rows = _wait_for_file(api, dst_name, expected)
    if row is None:
        elsewhere = [str(r.get("name")) for r in rows or ()
                     if fw_plan._base_name(r.get("name")) == dst_name]
        where = " (found as {} - not a location RouterOS installs from)".format(", ".join(elsewhere)) if elsewhere else ""
        raise RuntimeError("{} not found on the router {}s after the download finished{} - fetch {} reported "
                           "downloaded={} KiB total={} KiB (repository file {} bytes); files on the router: {}".format(
                               dst_name, FILE_APPEAR_TIMEOUT, where, url, last.get("downloaded"), last.get("total"),
                               expected, _describe_files(rows)))
    try:
        size = int(row.get("size"))
    except (TypeError, ValueError):
        raise RuntimeError("{}: unexpected size value {!r}".format(dst_name, row.get("size")))
    if size != expected:
        raise RuntimeError("{}: size on router {} != repository {} (fetch {})".format(dst_name, size, expected, url))
    if step is not None and arch:
        prefix = arch + "-"
        pkg = firm.architecture[len(prefix):] if firm.architecture.startswith(prefix) else None
        problem = fw_plan.check_uploaded_package(row, step, arch, pkg, router_major)
        if problem:
            raise RuntimeError("{}: {} (fetch {})".format(dst_name, problem, url))


def _send_reboot(api):
    """Returns None when the reboot was accepted (the router closes the connection), or the
    refusal message (!trap)."""
    try:
        _call(api, "/system/reboot")
    except FatalError:
        return None
    except RouterTrap as e:
        return str(e)
    except (ConnectionClosed, OSError, socket.timeout):
        return None
    return None


# ---------------------------------------------------------------------------
# Database helpers (short connections, never held during router I/O)
# ---------------------------------------------------------------------------

Devices = db_device.Devices


def _load_dev(dev_id):
    with database.connection_context():
        return Devices.get_or_none(Devices.id == dev_id)


def _dev_update(dev_id, **fields):
    with database.connection_context():
        Devices.update(**fields).where(Devices.id == dev_id).execute()


def _sysconf(key, default=None):
    try:
        with database.connection_context():
            val = db_sysconfig.get_sysconfig(key)
        return default if val in (None, "") else val
    except Exception:
        return default


def _rules():
    """Update rules: Pro (safe upgrade steps, wireless packages) with a valid license,
    otherwise the free rules (target version directly)."""
    if ISPRO and fw_plan_pro is not None:
        try:
            if utilpro.check_license_dev_limit_exp():
                return fw_plan_pro
        except Exception as e:
            log.warning(f"License check for firmware rules failed: {e}")
    return fw_plan


def _max_retries():
    try:
        return int(_sysconf('firmware_max_retries', 2))
    except (TypeError, ValueError):
        return 2


def _event(dev_id, detail, level, comment):
    try:
        with database.connection_context():
            db_events.firmware_event(dev_id, "updater", detail, level, 0, comment)
    except Exception as e:
        log.error(f"Could not store firmware event for device {dev_id}: {e}")


FAILURE_EVENTS = ("Update Failed", "Download Failed", "Device storage", "Firmware repositpry", "Package Corrupt",
                  "Firmware Upgrade")


def _fix_events(dev_id, details=FAILURE_EVENTS):
    try:
        with database.connection_context():
            events = list(db_events.get_events_by_src_and_status("updater", 0, dev_id).dicts())
            for d in details:
                util.check_or_fix_event(events, "firmware", d)
    except Exception as e:
        log.warning(f"Could not close firmware events for device {dev_id}: {e}")


def _report(q, dev_id, ok, **extra):
    if q is not None:
        item = {"id": dev_id, "status": bool(ok)}
        item.update(extra)
        q.put(item)


def _fail(dev, reason, q=None, event="Update Failed", severity="Critical", permanent=False):
    """Mark the device failed. A permanent failure blocks automatic retries (retrying
    cannot help until something is changed); otherwise the attempt counter grows."""
    dev_id = dev.id if hasattr(dev, "id") else dev
    max_r = _max_retries()
    cur = _load_dev(dev_id)
    attempts = int(getattr(cur, "failed_attempt", 0) or 0) + 1
    if permanent:
        attempts = max(attempts, max_r)
    _dev_update(dev_id, status="failed", failed_attempt=attempts)
    _event(dev_id, event, severity, reason)
    rec = fw_state.get_record(dev_id) or {}
    rec.update(state="failed", reason=reason, permanent=bool(permanent), failed_at=time.time(),
               next_try_at=time.time() + RETRY_BACKOFF)
    fw_state.put_record(dev_id, rec)
    log.error(f"Firmware update of device {dev_id}: {reason}")
    _report(q, dev_id, False, reason=reason)
    return False


# ---------------------------------------------------------------------------
# Target version
# ---------------------------------------------------------------------------

def resolve_final_target(dev, installed, version_to_install=None, ofa=None):
    """Final version for a device. 'keep' policy (old_firmware_action) keeps v6 devices on
    the configured v6 version whatever form the request has."""
    installed = fw_plan.ver(installed)
    ofa = ofa or _sysconf('old_firmware_action', 'keep')
    keep_v6 = (ofa == "keep" and installed.major <= 6)
    requested = None
    if version_to_install:
        if isinstance(version_to_install, dict):
            if keep_v6 and version_to_install.get("version_to_install_6"):
                requested = version_to_install["version_to_install_6"]
            else:
                requested = version_to_install.get("version_to_install") or version_to_install.get("version")
        else:
            requested = version_to_install
    elif getattr(dev, "firmware_to_install", None):
        requested = dev.firmware_to_install
    if requested in (None, "", False):
        requested = _sysconf('old_version') if keep_v6 else _sysconf('latest_version')
    if requested in (None, "", False):
        raise PlanError("no_target", "No target firmware version configured (Settings > Firmware)",
                        event="Firmware repositpry", severity="Error")
    try:
        target = fw_plan.ver(requested)
    except Exception:
        raise PlanError("bad_target", f"Invalid target version '{requested}'", event="Update Failed", severity="Error")
    if keep_v6 and target.major >= 7:
        old = _sysconf('old_version')
        try:
            old_v = fw_plan.ver(old) if old else None
        except Exception:
            old_v = None
        if not old_v or old_v.major >= 7:
            raise PlanError("keep_v6", "Firmware policy keeps v6 devices on v6 but no v6 version is configured",
                            event="Update Failed", severity="Error")
        log.info(f"Device {dev.name}: v6 kept on v6 by policy - target {old_v.canonical()} instead of {target.canonical()}")
        target = old_v
    return target


# ---------------------------------------------------------------------------
# Update engine
# ---------------------------------------------------------------------------

def update_device(dev, q, version_to_install=None, ofa=None, packages_mode="full", packages_to_install=None,
                  auto_upgrade_rb=True, _leased=False):
    """Run one update step on a device (synchronously, under the device lease).

    Returns True when the step was started (router rebooting) or nothing was needed, False
    otherwise. The final result of a reboot is checked by the firmware mule
    (verify_device_firmware) which also starts the next step of a multi-step upgrade.
    """
    dev_id = dev.id
    token = None
    if not _leased:
        token = fw_state.acquire(dev_id)
        if not token:
            _report(q, dev_id, False, reason="Firmware operation already in progress for this device")
            return False
        if job_control.device_locked(dev_id):
            fw_state.release(dev_id, token)
            _report(q, dev_id, False, reason="A backup / snippet job is working on this device - try again later")
            return False
    try:
        return _update_device_locked(dev_id, q, version_to_install, ofa, packages_mode, packages_to_install, auto_upgrade_rb)
    except PlanError as e:
        return _fail(dev_id, e.message, q, event=e.event, severity=e.severity, permanent=e.permanent)
    except Exception as e:
        log.exception(f"Firmware update of device {dev_id} failed")
        return _fail(dev_id, f"Firmware update error: {e}", q)
    finally:
        if token:
            fw_state.release(dev_id, token)


def _update_device_locked(dev_id, q, version_to_install, ofa, packages_mode, packages_to_install, auto_upgrade_rb):
    dev = _load_dev(dev_id)
    if dev is None:
        _report(q, dev_id, False, reason="Device not found")
        return False
    port = util.get_device_port(dev)
    if not util.check_port(dev.ip, port):
        rec = fw_state.get_record(dev_id) or {}
        if rec:
            rec["next_try_at"] = time.time() + UNREACHABLE_BACKOFF
            fw_state.put_record(dev_id, rec)
        _report(q, dev_id, False, reason=f"Device unreachable with port {port}")
        return False

    router = None
    try:
        try:
            router, api = _connect(dev)
            state = _read_state(api)
        except Exception as e:
            raise PlanError("connect_failed", f"Could not read the router: {e}", permanent=False,
                            event="Update Failed", severity="Error")
        if not state["version"]:
            raise PlanError("no_version", "Router did not report its RouterOS version", permanent=False)
        live = fw_plan.ver(state["version"])
        if str(dev.current_firmware or "") != live.canonical():
            _dev_update(dev_id, current_firmware=live.canonical())
        arch = state["arch"]
        if not arch:
            raise PlanError("unknown_arch", f"Unsupported architecture '{state['arch_name']}'", event="Update Failed")

        rules = _rules()
        if packages_mode == "packages_only":
            # extra packages only: RouterOS itself stays on the installed version
            final = step = live
        else:
            final = resolve_final_target(dev, live, version_to_install, ofa)
            if str(dev.firmware_to_install or "") != final.canonical():
                _dev_update(dev_id, firmware_to_install=final.canonical())
            if live >= final:
                return _already_up_to_date(dev, router, api, state, q)
            safe_install = _sysconf('safe_install', 'True') != "False"
            step = rules.next_step(live, final, rules.v6_bridge(_sysconf('old_version')), safe_install)

        legacy = None
        if packages_mode != "packages_only" and rules.crosses_wireless_split(live, step):
            legacy = rules.legacy_wireless_in_use(lambda path: _print_optional(api, path))
        main, extras, notes = rules.required_packages(
            live, step, arch, state["rows"], mode=packages_mode, selection=packages_to_install,
            legacy_wireless_in_use=legacy, rb_model=state["rb"].get("model", ""), board_name=state["board"])
        for n in notes:
            log.info(f"Device {dev.name} ({dev.ip}): {n}")
        if packages_mode == "firmware_only":
            left = [n for n in notes if n.startswith("firmware only: package(s)")]
            if left:
                _event(dev_id, "Package Check", "Warning", left[0])

        firms = []
        if main:
            firms.append(ensure_firmware(step, arch))
        # a selected package that is not installed yet is skipped (with an event) when it does
        # not exist for this version / architecture; an installed one fails the update
        installed = set(fw_plan.installed_packages(state["rows"], live))
        skipped = []
        for pkg in extras:
            try:
                firms.append(ensure_firmware(step, arch, pkg))
            except PlanError:
                if pkg in installed:
                    raise
                skipped.append(pkg)
        if skipped:
            extras = [p for p in extras if p not in skipped]
            _event(dev_id, "Package Check", "Warning",
                   "Selected package(s) {} not available for RouterOS {} ({}) - not installed".format(
                       ", ".join(skipped), step.canonical(), arch))
        if not main and not extras:
            _dev_update(dev_id, status="active", failed_attempt=0)
            fw_state.clear_record(dev_id)
            _report(q, dev_id, True, message="All packages already match the installed version")
            return True

        _dev_update(dev_id, status="updating")
        rec = fw_state.get_record(dev_id) or {}
        rec.update(state="transferring", kind="os", step=step.canonical(), final=final.canonical(),
                   started_at=time.time(), recoveries=rec.get("recoveries", 0))
        fw_state.put_record(dev_id, rec)

        if _sysconf('firmware_backup_before_update', 'True') != "False":
            ok = _firmware_backup(dev, api)
            if not ok and _sysconf('firmware_require_backup', 'False') == "True":
                raise PlanError("backup_failed", "Configuration backup before the update failed (backup required by settings)",
                                permanent=False)

        return apply_firmware(dev, router, api, state, step, final, firms, extras, q, auto_upgrade_rb=auto_upgrade_rb)
    finally:
        _close(router)


def _already_up_to_date(dev, router, api, state, q):
    dev_id = dev.id
    _fix_events(dev_id)
    fw_state.clear_record(dev_id)
    _dev_update(dev_id, firmware_to_install=None, failed_attempt=0)
    rb = state.get("rb") or {}
    if dev.upgrade_device and _routerboot_upgrade_available(rb):
        return _start_routerboot(dev, api, rb, q)
    _dev_update(dev_id, status="active", upgrade_device=False)
    _report(q, dev_id, True, message="Already up to date")
    return True


def apply_firmware(dev, router, api, state, step, final, firms, extras, q, auto_upgrade_rb=True):
    """Upload the package set to the router and reboot it. Nothing is left on the router
    when this fails before the reboot."""
    dev_id = dev.id
    own, foreign = fw_plan.classify_device_files(state["files"])
    if foreign:
        names = ", ".join(sorted(str(r.get("name")) for r in foreign))
        raise PlanError("foreign_packages", f"Package files already on the router would be installed at the next "
                                            f"reboot: {names}. Remove them first.", event="Update Failed")
    total = sum(os.path.getsize(f.location) for f in firms)
    try:
        free = int(state["free"])
    except (TypeError, ValueError):
        raise PlanError("free_space_unknown", "Router did not report free storage space", permanent=False,
                        event="Device storage")
    reclaim = 0
    for r in own:
        try:
            reclaim += int(r.get("size") or 0)
        except (TypeError, ValueError):
            pass
    needed = total + FREE_SPACE_MARGIN
    if free + reclaim < needed:
        raise PlanError("no_space", "Insufficient storage: {:.1f} MiB free, {:.1f} MiB needed for {} package(s)".format(
            (free + reclaim) / 1048576.0, needed / 1048576.0, len(firms)), permanent=True, event="Device storage")
    if own and _remove_files(api, own):
        raise PlanError("cleanup_failed", "Could not remove package files left by an earlier attempt", permanent=False)

    server_url = _server_url(dev)
    if not server_url:
        raise PlanError("no_server_url", "MikroWizard server address unknown (Settings: system URL)", event="Update Failed")

    xfer_router = None
    uploaded = []
    try:
        xfer_router, xfer_api = _connect(dev, timeout=TRANSFER_API_TIMEOUT)
        for firm in firms:
            dst = fw_plan.own_file_name(firm.architecture, step)
            uploaded.append(dst)
            _fetch_to_router(xfer_api, dev, firm, dst, server_url, step=step, arch=state["arch"],
                             router_major=fw_plan.ver(state["version"]).major)
    except Exception as e:
        _close(xfer_router)
        xfer_router = None
        cleaned = _cleanup_own_files(dev)
        reason = f"Package transfer failed: {e}"
        if not cleaned:
            reason += " - WARNING: uploaded packages could not be removed from the router; they will be installed at its next reboot"
        low = str(e).lower()
        storage = "space" in low or "disk" in low
        _fail(dev, reason, q, event="Device storage" if storage else "Download Failed", severity="Critical",
              permanent=storage)
        return False
    finally:
        _close(xfer_router)

    try:
        _fix_events(dev_id, ("Device storage", "Download Failed", "Firmware repositpry"))
        if auto_upgrade_rb and fw_plan._truthy((state.get("rb") or {}).get("routerboard")):
            try:
                _call(api, "/system/routerboard/settings/set", **{"auto-upgrade": "yes"})
            except Exception as e:
                log.warning(f"Could not enable RouterBOOT auto-upgrade on {dev.name}: {e}")
        pkgs_before = sorted(n for n, p in fw_plan.installed_packages(state["rows"], state["version"]).items()
                             if not p["disabled"])
        rec = fw_state.get_record(dev_id) or {}
        rec.update(state="rebooting", kind="os", step=step.canonical(), final=final.canonical(),
                   from_version=fw_plan.vstr(state["version"]), reboot_at=time.time(), uptime_before=state["uptime"],
                   packages_before=pkgs_before, expected_extras=list(extras), uploaded=uploaded)
        if not fw_state.put_record(dev_id, rec):
            raise RuntimeError("update record could not be stored (redis)")
    except Exception as e:
        cleaned = _cleanup_own_files(dev)
        return _fail(dev, "Update aborted before reboot: {}{}".format(
            e, "" if cleaned else " - WARNING: uploaded packages could not be removed from the router"), q)

    reboot_router = None
    try:
        reboot_router, reboot_api = _connect(dev)
    except Exception as e:
        _close(reboot_router)
        fw_state.update_record(dev_id, state="transferring")
        cleaned = _cleanup_own_files(dev)
        return _fail(dev, "Router not reachable for the reboot after the transfer: {}{}".format(
            e, "" if cleaned else " - WARNING: uploaded packages could not be removed from the router"), q)
    try:
        refused = _send_reboot(reboot_api)
    finally:
        _close(reboot_router)
    if refused:
        cleaned = _cleanup_own_files(dev)
        reason = f"Router refused the reboot: {refused}"
        if not cleaned:
            reason += " - WARNING: uploaded packages are still on the router"
        return _fail(dev, reason, q, permanent=True)
    _dev_update(dev_id, status="rebooting")
    log.info(f"Device {dev.name} ({dev.ip}): {len(firms)} package(s) for {step.canonical()} uploaded, rebooting")
    _report(q, dev_id, True, message=f"Rebooting to install {step.canonical()}")
    return True


# ---------------------------------------------------------------------------
# Verification after reboot (firmware mule)
# ---------------------------------------------------------------------------

def _reboot_timeout():
    return int(getattr(config, "FIRMWARE_REBOOT_TIMEOUT", 900))


def verify_device_firmware(dev, now=None):
    """Check a router that was rebooted for an update. Returns
    'wait' (not back yet / not rebooted yet), 'done', 'next_step', 'failed' or 'skip'."""
    dev_id = dev.id
    token = fw_state.acquire(dev_id)
    if not token:
        return "skip"
    try:
        return _verify_locked(dev_id, now)
    except Exception as e:
        log.exception(f"Verification of device {dev_id} failed")
        return "wait"
    finally:
        fw_state.release(dev_id, token)


def _verify_locked(dev_id, now=None):
    now = time.time() if now is None else now
    dev = _load_dev(dev_id)
    if dev is None:
        fw_state.clear_record(dev_id)
        return "skip"
    rec = fw_state.get_record(dev_id)
    if not rec or rec.get("state") != "rebooting":
        if dev.status in ("rebooting", "upgrading") or (dev.status == "updated" and dev.firmware_to_install):
            # Started before this version (no record): give it the full reboot timeout from now
            rec = {"state": "rebooting", "kind": "routerboot" if dev.status == "upgrading" else "os",
                   "final": dev.firmware_to_install, "step": dev.firmware_to_install, "reboot_at": now,
                   "legacy": True}
            fw_state.put_record(dev_id, rec)
        return "wait"
    elapsed = now - float(rec.get("reboot_at") or now)
    if elapsed < REBOOT_MIN_WAIT:
        return "wait"
    port = util.get_device_port(dev)
    router = None
    try:
        if not util.check_port(dev.ip, port):
            raise ConnectionError("port closed")
        router, api = _connect(dev)
        res = _print(api, "/system/resource")[0]
        live = fw_plan.ver(str(res.get("version") or "").partition(" ")[0])
        uptime = fw_plan.parse_uptime(res.get("uptime"))
        rows = _print(api, "/system/package")
        rb_rows = []
        if rec.get("kind") == "routerboot":
            rb_rows = _print(api, "/system/routerboard")
    except Exception as e:
        _close(router)
        if elapsed > _reboot_timeout():
            _fail(dev, "Router did not come back {} min after the update reboot ({})".format(int(elapsed // 60), e),
                  permanent=True)
            return "failed"
        return "wait"
    try:
        rebooted = uptime is not None and uptime <= elapsed + 60
        if not rebooted and not rec.get("legacy"):
            if elapsed > float(rec.get("reboot_grace") or REBOOT_NOT_STARTED):
                cleaned = _cleanup_own_files(dev, api)
                _fail(dev, "Router did not reboot after the reboot command (uptime {}s); uploaded packages {}".format(
                    uptime, "removed" if cleaned else "could NOT be removed"), permanent=False)
                return "failed"
            return "wait"
        if str(dev.current_firmware or "") != live.canonical():
            _dev_update(dev_id, current_firmware=live.canonical())
        kind = rec.get("kind", "os")
        if kind == "routerboot":
            rb = rb_rows[0] if rb_rows else {}
            if str(rb.get("current-firmware") or "") == str(rb.get("upgrade-firmware") or "") and rb.get("current-firmware"):
                _dev_update(dev_id, status="updated", upgrade_device=False, upgrade_availble=False, failed_attempt=0)
                _fix_events(dev_id, ("Firmware Upgrade",))
                fw_state.clear_record(dev_id)
                return "done"
            _fail(dev, "RouterBOOT still {} after the upgrade reboot (expected {})".format(
                rb.get("current-firmware"), rb.get("upgrade-firmware")), event="Firmware Upgrade", severity="Error")
            return "failed"

        final = fw_plan.ver(rec.get("final") or dev.firmware_to_install or live)
        step = fw_plan.ver(rec.get("step") or final)
        if live >= final:
            _finish_os_update(dev, rec, rows, live)
            return "done"
        if live >= step:
            _dev_update(dev_id, status="updating", failed_attempt=0)
            _fix_events(dev_id)
            rec.update(state="next_step", step_done=step.canonical(), next_try_at=now)
            fw_state.put_record(dev_id, rec)
            log.info(f"Device {dev.name} ({dev.ip}) reached intermediate version {live.canonical()}, next step towards {final.canonical()}")
            return "next_step"
        cleaned = _cleanup_own_files(dev, api)
        reason = "Router rebooted but still runs {} - {} was not installed{}".format(
            live.canonical(), step.canonical(), _install_log_hint(api))
        if not cleaned:
            reason += " (uploaded packages could NOT be removed)"
        _fail(dev, reason)
        return "failed"
    finally:
        _close(router)


def _install_log_hint(api):
    """Last package installation error from the router log, if any."""
    try:
        for row in reversed(_print(api, "/log")[-200:]):
            msg = str(row.get("message") or "")
            if any(w in msg.lower() for w in ("install", "package", "npk")):
                return " (router log: {})".format(msg[:200])
    except Exception:
        pass
    return ""


def _finish_os_update(dev, rec, rows, live):
    dev_id = dev.id
    after = {n for n, p in fw_plan.installed_packages(rows, live).items() if not p["disabled"]}
    expected = set(rec.get("expected_extras") or [])
    if rec.get("kind") == "native":
        # the router chose the packages itself: everything active before must still be active
        expected = _rules().native_expected_packages(rec.get("packages_before") or [], after)
    missing = sorted(expected - after)
    fields = dict(status="updated", firmware_to_install=None, failed_attempt=0, update_availble=False)
    _dev_update(dev_id, **fields)
    _fix_events(dev_id, ("Update Failed", "Download Failed", "Device storage", "Firmware repositpry", "Package Corrupt"))
    if missing:
        _event(dev_id, "Package Check", "Critical",
               "Updated to {} but package(s) {} are not active after the reboot".format(live.canonical(), ", ".join(missing)))
    fw_state.clear_record(dev_id)
    log.info(f"Device {dev.name} ({dev.ip}) successfully updated to {live.canonical()}")
    if dev.upgrade_device:
        fw_state.put_record(dev_id, {"state": "queued", "seq": fw_state.next_queue_seq(), "queued_at": time.time(),
                                     "request": {"kind": "routerboot"}, "origin": "after-update"})


# ---------------------------------------------------------------------------
# RouterBOOT
# ---------------------------------------------------------------------------

def _routerboot_upgrade_available(rb):
    if not rb or not fw_plan._truthy(rb.get("routerboard")):
        return False
    cur, upg = str(rb.get("current-firmware") or ""), str(rb.get("upgrade-firmware") or "")
    if not cur or not upg or cur == upg:
        return False
    try:
        return fw_plan.ver(upg) > fw_plan.ver(cur)
    except Exception:
        return False


def _start_routerboot(dev, api, rb, q):
    dev_id = dev.id
    try:
        _call(api, "/system/routerboard/upgrade")
    except Exception as e:
        return _fail(dev, f"RouterBOOT upgrade command failed: {e}", q, event="Firmware Upgrade", severity="Error",
                     permanent=_no_such_command(e))
    fw_state.put_record(dev_id, {"state": "rebooting", "kind": "routerboot", "reboot_at": time.time(),
                                 "rb_from": rb.get("current-firmware"), "rb_to": rb.get("upgrade-firmware")})
    refused = _send_reboot(api)
    if refused:
        return _fail(dev, f"Router refused the reboot: {refused}", q, event="Firmware Upgrade", severity="Error", permanent=True)
    _dev_update(dev_id, status="upgrading")
    _report(q, dev_id, True, message="RouterBOOT upgrade, rebooting")
    return True


def upgrade_routerboot(dev, q=None, router=None, _leased=False):
    """RouterBOOT upgrade (+ reboot) when the router has a newer RouterBOOT available.
    The result is verified by the firmware mule after the reboot."""
    dev_id = dev.id
    token = None if _leased else fw_state.acquire(dev_id)
    if not token and not _leased:
        _report(q, dev_id, False, reason="Firmware operation already in progress for this device")
        return False
    if token and job_control.device_locked(dev_id):
        fw_state.release(dev_id, token)
        _report(q, dev_id, False, reason="A backup / snippet job is working on this device - try again later")
        return False
    own = router is None
    try:
        if own:
            if not util.check_port(dev.ip, util.get_device_port(dev)):
                _report(q, dev_id, False, reason="Device unreachable")
                return False
            router, api = _connect(dev)
        else:
            api = router._connect_api()
        try:
            rb_rows = _print(api, "/system/routerboard")
        except RouterTrap as e:
            if _no_such_command(e):
                rb_rows = []
            else:
                raise
        rb = rb_rows[0] if rb_rows else {}
        if not _routerboot_upgrade_available(rb):
            _dev_update(dev_id, upgrade_device=False, upgrade_availble=False,
                        status="active" if dev.status in ("upgrading", "updating", "failed") else dev.status)
            fw_state.clear_record(dev_id)
            _report(q, dev_id, True, message="No RouterBOOT upgrade available")
            return True
        return _start_routerboot(dev, api, rb, q)
    except Exception as e:
        return _fail(dev, f"RouterBOOT upgrade failed: {e}", q, event="Firmware Upgrade", severity="Error")
    finally:
        if own:
            _close(router)
        if token:
            fw_state.release(dev_id, token)



def reboot_device(dev, by=""):
    """Reboot a MikroTik router (devices list batch action). Returns (ok, reason).

    Takes the device lease, so a router in a firmware update is never rebooted from here (and
    no update starts during the reboot); a router a backup / snippet job is working on is
    skipped. The device status is not changed: 'rebooting' would make the firmware mule
    verify an update that never ran."""
    dev_id = dev.id
    token = fw_state.acquire(dev_id)
    if not token:
        return False, "Firmware operation in progress"
    router = None
    try:
        if job_control.device_locked(dev_id):
            return False, "A backup / snippet job is working on this device"
        if not util.check_port(dev.ip, util.get_device_port(dev)):
            return False, "Device unreachable"
        router, api = _connect(dev)
        try:
            _call(api, "/system/reboot")
        except RouterTrap:
            raise                       # the router refused (e.g. user without reboot permission)
        except Exception as e:
            # the router closes the API session while it goes down: the command was sent
            log.debug(f"Reboot of {dev.name}: connection closed ({e})")
        try:
            with database.connection_context():
                db_events.config_event(dev_id, "MikroWizard", "Device Reboot", "info", 1,
                                       "Router rebooted from the devices list" + (" by " + by if by else ""))
        except Exception as e:
            log.warning(f"Could not store reboot event for device {dev_id}: {e}")
        return True, ""
    except Exception as e:
        log.error(f"Reboot of device {dev_id} failed: {e}")
        return False, str(e)
    finally:
        _close(router)
        fw_state.release(dev_id, token)

# ---------------------------------------------------------------------------
# Native update (router downloads from MikroTik itself)
# ---------------------------------------------------------------------------

def update_device_native(dev, q=None, channel=None, auto_upgrade_rb=True, ofa=None, _leased=False):
    """Router updates itself with /system/package/update (needs internet access on the
    router; it downloads every installed package). Verified by the mule after the reboot.
    channel: set the router's update channel first; None keeps the router's own channel."""
    dev_id = dev.id
    token = None if _leased else fw_state.acquire(dev_id)
    if not token and not _leased:
        _report(q, dev_id, False, reason="Firmware operation already in progress for this device")
        return False
    if token and job_control.device_locked(dev_id):
        fw_state.release(dev_id, token)
        _report(q, dev_id, False, reason="A backup / snippet job is working on this device - try again later")
        return False
    router = None
    try:
        dev = _load_dev(dev_id) or dev
        if not util.check_port(dev.ip, util.get_device_port(dev)):
            _report(q, dev_id, False, reason="Device unreachable")
            return False
        router, api = _connect(dev, timeout=60)
        state = _read_state(api)
        live = fw_plan.ver(state["version"])
        if channel:
            if channel not in ("stable", "long-term", "testing", "development"):
                raise PlanError("bad_channel", f"Unsupported update channel '{channel}'", event="Update Failed")
            _call(api, "/system/package/update/set", channel=channel)
        replies = _call(api, "/system/package/update/check-for-updates")
        info = {}
        for r in replies:
            info.update(r)
        status = str(info.get("status", "")).lower()
        latest = str(info.get("latest-version") or "")
        if not latest or "error" in status or "could not" in status:
            raise PlanError("check_failed", f"Router could not check for updates: {info.get('status')}", permanent=False)
        latest_v = fw_plan.ver(latest)
        if latest_v <= live or "up to date" in status:
            return _already_up_to_date(dev, router, api, state, q)
        if latest_v.is_prerelease and channel not in ("testing", "development"):
            raise PlanError("prerelease", f"Router offers pre-release {latest} (router update channel "
                            f"'{info.get('channel')}') - not installed; choose the channel explicitly", event="Update Failed",
                            severity="Error")
        ofa = ofa or _sysconf('old_firmware_action', 'keep')
        if live.major <= 6 and latest_v.major >= 7 and ofa == "keep":
            raise PlanError("keep_v6", f"Native update offers {latest}; policy keeps v6 devices on v6", event="Update Failed",
                            severity="Error")
        own, foreign = fw_plan.classify_device_files(state["files"])
        if foreign:
            raise PlanError("foreign_packages", "Package files already on the router: " +
                            ", ".join(str(r.get("name")) for r in foreign), event="Update Failed")
        if own:
            _remove_files(api, own)
        if auto_upgrade_rb and fw_plan._truthy((state.get("rb") or {}).get("routerboard")):
            try:
                _call(api, "/system/routerboard/settings/set", **{"auto-upgrade": "yes"})
            except Exception as e:
                log.warning(f"Could not enable RouterBOOT auto-upgrade on {dev.name}: {e}")
        if _sysconf('firmware_backup_before_update', 'True') != "False":
            _firmware_backup(dev, api)
        pkgs_before = sorted(n for n, p in fw_plan.installed_packages(state["rows"], live).items() if not p["disabled"])
        prev_req = (fw_state.get_record(dev_id) or {}).get("request") or {"kind": "update", "delivery_method": "native",
                                                                           "channel": channel}
        fw_state.put_record(dev_id, {"request": prev_req, "state": "rebooting", "kind": "native", "step": latest_v.canonical(),
                                     "final": latest_v.canonical(), "from_version": live.canonical(),
                                     "reboot_at": time.time(), "reboot_grace": 1800, "uptime_before": state["uptime"],
                                     "packages_before": pkgs_before, "expected_extras": []})
        _dev_update(dev_id, status="updating", firmware_to_install=latest_v.canonical())
        try:
            _call(api, "/system/package/update/install")
        except RouterTrap as e:
            if not isinstance(e, FatalError):
                raise PlanError("install_refused", f"Router refused the update: {e}", permanent=False)
        except (FatalError, ConnectionClosed, OSError, socket.timeout):
            pass                       # router downloads, then reboots and drops the session
        _dev_update(dev_id, status="rebooting")
        _report(q, dev_id, True, message=f"Router installing {latest_v.canonical()}")
        return True
    except PlanError as e:
        return _fail(dev, e.message, q, event=e.event, severity=e.severity, permanent=e.permanent)
    except Exception as e:
        log.exception(f"Native update of device {dev_id} failed")
        return _fail(dev, f"Native update error: {e}", q, event="Native Update Failed")
    finally:
        _close(router)
        if token:
            fw_state.release(dev_id, token)


# ---------------------------------------------------------------------------
# Queue (requests are executed by the firmware mule)
# ---------------------------------------------------------------------------

UPDATE_MODES = ("full", "firmware_only")


def update_request_error(request):
    """Reason a firmware update request cannot be queued, None when it is valid. Modes:
    'full' and 'firmware_only'; Router Native updates RouterOS and every installed package
    itself, so it is always 'full'."""
    if request.get("kind", "update") != "update":
        return None
    mode = request.get("mode") or "full"
    if mode not in UPDATE_MODES:
        return "Update scope '{}' is not supported (use full or firmware_only)".format(mode)
    if request.get("delivery_method") == "native" and mode != "full":
        return "Router Native updates RouterOS and all packages; scope '{}' is not possible".format(mode)
    return None


def enqueue_device_updates(devices, request, origin="manual", check_reachable=True):
    """Queue a firmware request for each device. The firmware mule runs them (no time
    limit, survives restarts). Returns [{"id", "status", "reason"}]."""
    results = []
    reason = update_request_error(request)
    if reason:
        return [{"id": dev.id, "status": False, "reason": reason} for dev in devices]
    for dev in devices:
        dev_id = dev.id
        if getattr(dev, "device_type", None) and dev.device_type != "mikrotik":
            continue
        if check_reachable and not util.check_port(dev.ip, util.get_device_port(dev)):
            results.append({"id": dev_id, "status": False, "reason": "Device unreachable"})
            continue
        token = fw_state.acquire(dev_id)
        if not token:
            results.append({"id": dev_id, "status": False, "reason": "Firmware operation already in progress"})
            continue
        try:
            cur = _load_dev(dev_id) or dev
            prev = fw_state.get_record(dev_id) or {}
            if prev.get("state") in ("rebooting", "transferring") or cur.status in ("rebooting", "upgrading"):
                results.append({"id": dev_id, "status": False,
                                "reason": "Router is rebooting for an update - wait for the result first"})
                continue
            rec = {"state": "queued", "request": request, "seq": fw_state.next_queue_seq(), "queued_at": time.time(),
                   "origin": origin, "prev_status": cur.status or "active", "prev_fti": cur.firmware_to_install,
                   "prev_failed_attempt": cur.failed_attempt or 0, "prev_upgrade_device": bool(cur.upgrade_device),
                   "prev_record": prev or None, "next_try_at": 0}
            if not fw_state.put_record(dev_id, rec):
                results.append({"id": dev_id, "status": False, "reason": "Could not queue (redis unavailable)"})
                continue
            fields = {"status": "updating", "failed_attempt": 0}
            if request.get("kind") == "routerboot":
                fields["upgrade_device"] = True
            _dev_update(dev_id, **fields)
            results.append({"id": dev_id, "status": True, "message": "queued"})
        finally:
            fw_state.release(dev_id, token)
    return results


def cancel_queued_updates(dev_ids=None):
    """Remove queued (not yet started) firmware requests; devices get their previous
    status back. Devices being updated right now are not interrupted. Returns the count."""
    with database.connection_context():
        query = Devices.select(Devices.id).where(Devices.status == "updating")
        if dev_ids:
            query = query.where(Devices.id.in_(list(dev_ids)))
        ids = [d.id for d in query]
    recs = fw_state.get_records(ids)
    cancelled = 0
    for dev_id, rec in recs.items():
        if rec.get("state") not in ("queued", "next_step"):
            continue
        token = fw_state.acquire(dev_id)
        if not token:
            continue
        try:
            rec = fw_state.get_record(dev_id) or {}
            if rec.get("state") not in ("queued", "next_step"):
                continue
            if rec.get("state") == "queued":
                prev_status = rec.get("prev_status") or "active"
                if prev_status in ("updating", "rebooting", "upgrading", "updated"):
                    prev_status = "active"
                _dev_update(dev_id, status=prev_status, firmware_to_install=rec.get("prev_fti"),
                            failed_attempt=rec.get("prev_failed_attempt") or 0,
                            upgrade_device=bool(rec.get("prev_upgrade_device")))
                if rec.get("prev_record") and prev_status == "failed":
                    fw_state.put_record(dev_id, rec["prev_record"])    # keeps 'permanent' (no auto retry)
                else:
                    fw_state.clear_record(dev_id)
            else:
                # multi-step upgrade stopped between two steps: stays on the intermediate version
                _dev_update(dev_id, status="active")
                fw_state.clear_record(dev_id)
                _event(dev_id, "Update Failed", "Warning",
                       "Multi-step update stopped by the operator after reaching {} (target {})".format(
                           rec.get("step_done") or rec.get("step"), rec.get("final")))
            cancelled += 1
        finally:
            fw_state.release(dev_id, token)
    return cancelled


def run_queued_request(dev_id):
    """Run the queued / next-step / retry work of one device (called by the firmware mule).
    The lease is taken first and the record re-read under it, so a Stop that happened in
    between is honoured."""
    token = fw_state.acquire(dev_id)
    if not token:
        return False
    try:
        if job_control.device_locked(dev_id):
            return False                  # a backup / snippet job is on the router: next tick
        return _run_queued_locked(dev_id)
    finally:
        fw_state.release(dev_id, token)


def _run_queued_locked(dev_id):
    rec = fw_state.get_record(dev_id) or {}
    req = rec.get("request") or {}
    dev = _load_dev(dev_id)
    if dev is None:
        fw_state.clear_record(dev_id)
        return False
    if not rec and dev.status != "failed" and dev.status != "updating":
        return False                      # cancelled / reset meanwhile
    q = queue.Queue()
    kind = req.get("kind", "update")
    if kind == "routerboot" and not dev.firmware_to_install:
        return upgrade_routerboot(dev, q, _leased=True)
    if req.get("delivery_method") == "native":
        return update_device_native(dev, q, channel=req.get("channel") or None,
                                    auto_upgrade_rb=req.get("auto_upgrade_rb", True), _leased=True)
    # the requested version only for the first run; later steps / retries / recoveries go to the
    # final target already stored on the device. Mode and package selection always come from
    # the original request (a 'packages only' job must never turn into an OS upgrade).
    version = req.get("version") if rec.get("state") == "queued" else None
    return update_device(dev, q, version_to_install=version, packages_mode=req.get("mode") or "full",
                         packages_to_install=req.get("packages"),
                         auto_upgrade_rb=req.get("auto_upgrade_rb", True), _leased=True)


def _task_version(data):
    """Version request of a scheduled task: the v6 version is kept for the 'keep v6' policy."""
    v = data.get('version_to_install')
    if not v:
        return None
    if data.get('version_to_install_6'):
        return {"version_to_install": v, "version_to_install_6": data['version_to_install_6']}
    return v


def run_firmware_task(utask):
    """Scheduled firmware task (Free tier): queue the devices for the firmware mule."""
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
    if strategy == 'latest':
        log.warning(f"Automated latest firmware update strategy is a Pro feature and is not available in Free tier. Skipping task {utask.id}.")
        return []
    native = strategy == 'native' or data.get('delivery_method') == 'native'
    request = {
        "kind": "update",
        "version": _task_version(data) if not native else None,
        "mode": data.get('mode', 'full') if not native else 'full',     # native updates everything
        "packages": data.get('packages') if not native else None,
        "auto_upgrade_rb": data.get('auto_upgrade_rb', True),
        "delivery_method": 'native' if native else 'local_repo',
    }
    return enqueue_device_updates(devices, request, origin="task:{}".format(utask.id))


# ---------------------------------------------------------------------------
# Compatibility helpers
# ---------------------------------------------------------------------------

def check_device_storage_preflight(router, required_mb=15):
    """(ok, free_mb). Fails closed: when free space cannot be read the answer is False."""
    try:
        if hasattr(router, 'api') and hasattr(router.api, 'path'):
            res = tuple(router.api.path('/system/resource'))
        elif hasattr(router, 'path'):
            res = tuple(router.path('/system/resource'))
        else:
            res = tuple(router('/system/resource/print'))
        free_mb = int(res[0]['free-hdd-space']) / (1024 * 1024)
        return free_mb >= required_mb, free_mb
    except Exception as e:
        log.warning(f"Could not check storage preflight: {e}")
        return False, 0.0


def verify_router_file(router, filename, expected_size=None):
    """True when filename is in the router's root (or flash/) folder with size > 0
    (and == expected_size when given)."""
    try:
        if hasattr(router, 'api') and hasattr(router.api, 'path'):
            files = tuple(router.api.path('/file'))
        elif hasattr(router, 'path'):
            files = tuple(router.path('/file'))
        else:
            files = tuple(router('/file/print'))
        row = fw_plan.find_file(files, filename.lstrip('/'))
        if not row:
            return False
        size = int(row.get('size', 0))
        return size > 0 and (expected_size is None or size == expected_size)
    except Exception as e:
        log.warning(f"Could not verify file {filename} on router: {e}")
    return False


def reset_device_update_status(dev_ids):
    """
    Reset failed update status and attempt counter for a list of device IDs.
    Clears open updater events and the update record (queued / multi-step state) so the
    device returns to normal active status.
    """
    if isinstance(dev_ids, str):
        dev_ids = [int(x.strip()) for x in dev_ids.split(',') if x.strip().isdigit()]
    elif isinstance(dev_ids, int):
        dev_ids = [dev_ids]
    
    if not dev_ids:
        return 0

    updated_count = 0
    for dev_id in dev_ids:
        fw_state.clear_record(dev_id)
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

