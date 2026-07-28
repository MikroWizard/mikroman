#!/usr/bin/python
# -*- coding: utf-8 -*-

# kek_provider.py: Loads, validates, and auto-provisions the Key Encryption Key (KEK)
# used for envelope encryption of PAM credentials.
#
# Design:
#   - On first call to get_kek(), checks config.KEK (from PYSRV_KEK in server-conf.json).
#   - If missing or empty, generates a new Fernet key, writes it back into
#     server-conf.json in-place, and updates config.KEK in memory — zero operator action
#     required for fresh installs or live updates.
#   - If present, validates it is a well-formed Fernet key before returning.
#   - Thread-safe (double-checked lock): concurrent requests on startup cannot produce
#     two different KEKs.
#   - Result is cached in _kek_cache for the lifetime of the process.
#
# The KEK is ONLY used to wrap per-credential DEKs (see envelope_crypto.py).
# It does NOT replace config.CRYPT_KEY, which continues to handle all existing
# encryption (device passwords stored in devices table, API tokens, etc.) unchanged.
#
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import json
import logging
import os
import threading

import config
from cryptography.fernet import Fernet

log = logging.getLogger("kek_provider")

# Module-level cache and lock
_kek_cache = None
_lock = threading.Lock()


def get_kek() -> bytes:
    """Return the KEK as bytes, generating and persisting it if not yet configured.

    Behavior:
      - PYSRV_KEK already set in server-conf.json → validate and return it.
      - PYSRV_KEK missing or empty → auto-generate a new Fernet key, write it to
        server-conf.json so it survives restarts, update config.KEK in memory,
        and return the new key.
      - PYSRV_KEK set but malformed → raise RuntimeError with a clear diagnostic.

    This function is safe to call from any thread at any time, including before
    the first HTTP request is served.
    """
    global _kek_cache

    # Fast path — already loaded
    if _kek_cache is not None:
        return _kek_cache

    with _lock:
        # Double-checked locking: another thread may have populated it while we waited
        if _kek_cache is not None:
            return _kek_cache

        raw = getattr(config, "KEK", "") or ""

        if not raw:
            # ── Auto-generate path ────────────────────────────────────────────
            new_key = Fernet.generate_key()  # URL-safe base64, 44 chars
            new_key_str = new_key.decode()
            _write_kek_to_config(new_key_str)  # persist before caching
            config.KEK = new_key_str  # keep in-process config in sync
            _kek_cache = new_key
            log.info(
                "PYSRV_KEK was not configured — a new KEK was generated and saved "
                "to server-conf.json. This key is now active and will be reused on "
                "every subsequent restart."
            )
        else:
            # ── Load + validate existing key ──────────────────────────────────
            try:
                key_bytes = raw.encode() if isinstance(raw, str) else raw
                Fernet(key_bytes)  # raises ValueError if malformed
                _kek_cache = key_bytes
                log.debug("KEK loaded from config and validated.")
            except Exception as exc:
                raise RuntimeError(
                    "PYSRV_KEK in server-conf.json is not a valid Fernet key: {}. "
                    "Either fix or remove the key (removing it will trigger "
                    "auto-generation of a new one, which will invalidate any "
                    "credentials already encrypted with the old key).".format(exc)
                )

        return _kek_cache


def _write_kek_to_config(kek_str: str) -> None:
    """Persist PYSRV_KEK into the server-conf.json file in-place.

    Reads the current JSON, adds/updates PYSRV_KEK, and writes it back with the
    same indentation as the rest of the file.

    Raises RuntimeError if the file cannot be read or written — the caller should
    surface this clearly rather than silently continuing without a persisted key.
    """
    conf_path = os.environ.get("PYSRV_CONFIG_PATH", "")
    if not conf_path:
        raise RuntimeError(
            "PYSRV_CONFIG_PATH environment variable is not set. "
            "Cannot persist the auto-generated KEK. "
            "Set PYSRV_KEK manually in your server configuration file."
        )

    try:
        with open(conf_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        raise RuntimeError(
            "Could not read server-conf.json at '{}' to persist KEK: {}".format(
                conf_path, exc
            )
        )

    data["PYSRV_KEK"] = kek_str

    try:
        with open(conf_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
            fh.write("\n")  # trailing newline for clean diffs
        log.info("Auto-generated PYSRV_KEK written to '%s'.", conf_path)
    except Exception as exc:
        raise RuntimeError(
            "Could not write PYSRV_KEK back to '{}': {}".format(conf_path, exc)
        )
