#!/usr/bin/python
# -*- coding: utf-8 -*-

# template_catalog.py: signed online updates of the system device templates
#
# A catalog (catalog.json + catalog.json.sig, Ed25519) lists every system template with a
# revision. Sources, newest wins: the copy bundled with the release (py/template_catalog/),
# mikrowizard.com (get_templates), GitHub releases (fallback), or a file an admin imports.
# Nothing is trusted without a valid signature of one of PUBLIC_KEYS.
#
# Applying never overwrites an admin's edit silently:
#   adopt  - the template already equals the catalog content: only the revision is recorded
#   new    - template missing: inserted as a system template
#   safe   - the template is unmodified since MikroWizard last set it: replaced
#   review - the admin edited it: per-field choice (fields the admin did not touch take the
#            new value, edited fields keep the admin's value unless chosen otherwise)
#   conflict - a custom (non-system) template already uses the same brand/os_type: shown, never
#            applied (the database allows one template per brand/os_type)
# display_name is owned by MikroWizard (read-only for system templates in the UI and API): it is
# always taken from the catalog and is not part of the content hash.
# Every change is saved in template_history first (revert = one click).
# Without migration 067 everything here is inactive and templates behave as before.
# MikroWizard.com , Mikrotik router management solution

import base64
import contextlib
import datetime
import hashlib
import json
import logging
import os
import re
import time

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from peewee import DateTimeField, IntegerField, TextField
from playhouse.postgres_ext import BinaryJSONField

from libs.db import db_sysconfig
from libs.db.db import BaseModel, database
from libs.db.db_pam import DeviceBrands, DeviceTemplates

try:
    from _version import __version__ as APP_VERSION
except ImportError:  # pragma: no cover
    APP_VERSION = "0"
try:
    from libs import utilpro  # noqa: F401 - Pro edition present
    ISPRO = True
except ImportError:
    ISPRO = False

log = logging.getLogger("template_catalog")

# Ed25519 public keys allowed to sign catalogs (base64, raw 32 bytes). A second key can be
# added before a key rotation.
PUBLIC_KEYS = [
    "31RHd/9+vUJb3zHgmw/3gMmOR5t+Ru6NM4yCb6fW2+M=",
]
FORMAT = 1
CONTENT_FIELDS = ("protocol", "connection", "prompt", "privilege_escalation", "commands", "pagination",
                  "error_patterns", "post_login_commands", "pre_logout_commands", "diff_exclusions",
                  "pre_connect", "post_disconnect", "config_mode")
DICT_MERGE_FIELDS = ("commands", "connection")          # merged per key
IDENTITY_FIELDS = ("brand", "os_type")
MANAGED_FIELDS = ("display_name",)                       # MikroWizard-owned, not hashed
KNOWN_FIELDS = IDENTITY_FIELDS + MANAGED_FIELDS + CONTENT_FIELDS
BUNDLED_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "template_catalog"))
UPDATE_URL = "https://mikrowizard.com/wp-json/mikrowizard/v1/get_templates"
GITHUB_URL = "https://github.com/MikroWizard/MikroWizrd-connection-template/releases/latest/download/"
CHECK_INTERVAL = 6 * 3600
MAX_CATALOG_BYTES = 2 * 1024 * 1024


class CatalogError(Exception):
    pass


class TemplateCatalog(BaseModel):
    catalog_version = IntegerField()
    channel = TextField(default="stable")
    origin = TextField()
    catalog = BinaryJSONField()
    signature = TextField()
    received_at = DateTimeField()

    class Meta:
        db_table = "template_catalog"


class TemplateCatalogState(BaseModel):
    template_id = IntegerField(primary_key=True)
    template_key = TextField()
    revision = IntegerField(default=0)
    baseline = BinaryJSONField(null=True)
    skipped_revision = IntegerField(default=0)
    updated_at = DateTimeField(null=True)

    class Meta:
        db_table = "template_catalog_state"


class TemplateHistory(BaseModel):
    template_id = IntegerField()
    template_key = TextField(null=True)
    revision = IntegerField(null=True)
    content = BinaryJSONField()
    reason = TextField()
    changed_by = TextField(null=True)
    changed_at = DateTimeField()

    class Meta:
        db_table = "template_history"


def _db():
    return database.connection_context() if database.is_closed() else contextlib.nullcontext()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def available():
    """Migration 067 ran (tables exist)."""
    try:
        with _db():
            return TemplateCatalog.table_exists() and TemplateCatalogState.table_exists() and TemplateHistory.table_exists()
    except Exception:
        return False


def _setting(key, default):
    try:
        with _db():
            value = db_sysconfig.get_sysconfig(key)
    except Exception:
        value = None
    return value if value not in (None, "") else default


def update_mode():
    mode = str(_setting("template_update_mode", "notify")).lower()
    return mode if mode in ("notify", "auto", "off") else "notify"


def channel():
    ch = str(_setting("template_channel", "stable")).lower()
    return ch if ch in ("stable", "beta") else "stable"


# ---------------------------------------------------------------------------
# content / hashing

def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_of(row):
    """The content fields of a template row (model or dict)."""
    get = row.get if isinstance(row, dict) else (lambda k, d=None: getattr(row, k, d))
    return {f: get(f, None) for f in CONTENT_FIELDS}


def snapshot(row):
    """Content fields plus display_name (history entries)."""
    out = content_of(row)
    get = row.get if isinstance(row, dict) else (lambda k, d=None: getattr(row, k, d))
    out["display_name"] = get("display_name", None)
    return out


def content_hash(content):
    return hashlib.sha256(_canon({f: content.get(f) for f in CONTENT_FIELDS}).encode("utf-8")).hexdigest()


def field_hash(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _untouched(entry, field, value):
    """The value is one MikroWizard shipped for this field in an earlier revision."""
    return field_hash(value) in set(((entry.get("previous_field_hashes") or {}).get(field)) or [])


def _key(brand, os_type):
    return "{}/{}".format(brand, os_type)


# ---------------------------------------------------------------------------
# signature / parsing

def verify(catalog_bytes, signature_b64):
    """Parsed catalog when the signature of one of PUBLIC_KEYS is valid, else CatalogError."""
    if not catalog_bytes or len(catalog_bytes) > MAX_CATALOG_BYTES:
        raise CatalogError("catalog missing or too large")
    try:
        sig = base64.b64decode(signature_b64.strip() if isinstance(signature_b64, str) else signature_b64)
    except Exception:
        raise CatalogError("signature is not base64")
    for key in PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(sig, catalog_bytes)
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise CatalogError("invalid catalog signature")
    try:
        catalog = json.loads(catalog_bytes.decode("utf-8"))
    except ValueError:
        raise CatalogError("catalog is not JSON")
    _validate(catalog)
    return catalog


def _validate(catalog):
    if catalog.get("format") != FORMAT or not isinstance(catalog.get("catalog_version"), int):
        raise CatalogError("unknown catalog format")
    seen = set()
    for t in catalog.get("templates") or []:
        c = t.get("content") or {}
        key = _key(c.get("brand"), c.get("os_type"))
        if t.get("key") != key or key in seen or not isinstance(t.get("revision"), int):
            raise CatalogError("bad template entry {}".format(t.get("key")))
        seen.add(key)
        for p in _regexes(c):
            try:
                re.compile(p)
            except Exception:
                raise CatalogError("bad pattern {!r} in {}".format(p, key))


def _regexes(content):
    """Every regular expression the device connector compiles from a template."""
    prompt = content.get("prompt") if isinstance(content.get("prompt"), dict) else {}
    esc = content.get("privilege_escalation") if isinstance(content.get("privilege_escalation"), dict) else {}
    pag = content.get("pagination") if isinstance(content.get("pagination"), dict) else {}
    out = list(prompt.get("patterns") or [])
    out += [prompt.get("login_pattern"), prompt.get("password_pattern"), esc.get("prompt"),
            esc.get("password_prompt"), esc.get("success_pattern"), pag.get("pattern")]
    ep = content.get("error_patterns")
    out += list((ep.get("patterns") or []) if isinstance(ep, dict) else (ep if isinstance(ep, list) else []))
    de = content.get("diff_exclusions")
    for rules in (de.values() if isinstance(de, dict) else []):
        for r in (rules if isinstance(rules, list) else []):
            out.append(r.get("pattern") if isinstance(r, dict) else r)
    return [p for p in out if isinstance(p, str) and p]


def _version_tuple(v):
    out = []
    for part in str(v or "0").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _app_version():
    return APP_VERSION


# ---------------------------------------------------------------------------
# storing catalogs

def latest():
    """(catalog dict, row) of the newest stored catalog, or (None, None)."""
    with _db():
        row = TemplateCatalog.select().order_by(TemplateCatalog.catalog_version.desc(), TemplateCatalog.id.desc()).first()
    return (row.catalog, row) if row else (None, None)


def store(catalog_bytes, signature_b64, origin, allow_older=False):
    """Verify and keep a catalog. Returns (stored, catalog_version)."""
    catalog = verify(catalog_bytes, signature_b64)
    current, _ = latest()
    if current and catalog["catalog_version"] <= current["catalog_version"] and not allow_older:
        return False, current["catalog_version"]
    with _db():
        TemplateCatalog.create(catalog_version=catalog["catalog_version"], channel=channel(), origin=origin,
                               catalog=catalog, signature=signature_b64.strip() if isinstance(signature_b64, str)
                               else base64.b64encode(signature_b64).decode(), received_at=_now())
    log.info("template catalog %s stored (%s)", catalog["catalog_version"], origin)
    return True, catalog["catalog_version"]


def load_bundled():
    """Store the catalog shipped with the release when it is newer than the stored one."""
    path = os.path.join(BUNDLED_DIR, "catalog.json")
    if not (os.path.exists(path) and os.path.exists(path + ".sig")):
        return False
    with open(path, "rb") as f:
        data = f.read()
    with open(path + ".sig", "r") as f:
        sig = f.read()
    return store(data, sig, "bundled")[0]


def fetch_remote(params):
    """Ask mikrowizard.com (then GitHub) for a newer catalog. params: serial_number, username,
    version, ISPRO. Returns (stored, message)."""
    current, _ = latest()
    have = current["catalog_version"] if current else 0
    body = dict(params, catalog_version=have, channel=channel())
    errors = []
    try:
        r = requests.post(UPDATE_URL, json=body, timeout=15)
        res = r.json() if r.status_code == 200 else {}
        if res.get("available") and res.get("catalog") and res.get("signature"):
            data = res["catalog"].encode("utf-8") if isinstance(res["catalog"], str) else res["catalog"]
            return store(data, res["signature"], "mikrowizard.com")[0], "catalog {} from mikrowizard.com".format(
                res.get("catalog_version"))
        if res and not res.get("error"):
            return False, "up to date"
        errors.append("mikrowizard.com: {}".format(res.get("error") or r.status_code))
    except Exception as e:
        errors.append("mikrowizard.com: {}".format(e))
    if channel() == "stable":
        try:
            r_cat = requests.get(GITHUB_URL + "catalog.json", timeout=15)
            r_sig = requests.get(GITHUB_URL + "catalog.json.sig", timeout=15)
            if r_cat.status_code != 200 or r_sig.status_code != 200:
                raise CatalogError("HTTP {}".format(r_cat.status_code if r_cat.status_code != 200 else r_sig.status_code))
            stored, version = store(r_cat.content, r_sig.text, "github")
            return stored, "catalog {} from GitHub".format(version) if stored else "up to date"
        except Exception as e:
            errors.append("github: {}".format(e))
    raise CatalogError("; ".join(errors))


# ---------------------------------------------------------------------------
# planning / applying

def _state_map():
    with _db():
        return {s.template_id: s for s in TemplateCatalogState.select()}


def plan():
    """Pending changes of the newest catalog: list of dicts (key, kind, revision, ...)."""
    catalog, _ = latest()
    if not catalog:
        return []
    is_pro = _is_pro()
    states = _state_map()
    with _db():
        rows = {_key(t.brand, t.os_type): t for t in DeviceTemplates.select()}
    app_version = _version_tuple(_app_version())
    out = []
    for entry in catalog.get("templates") or []:
        if entry.get("edition") == "pro" and not is_pro:
            continue
        if _version_tuple(entry.get("min_app_version")) > app_version:
            continue
        key, new = entry["key"], entry["content"]
        unknown = set(new) - set(KNOWN_FIELDS)
        if unknown:                                        # needs a newer MikroWizard
            log.debug("template %s skipped: fields %s unknown to this version", key, sorted(unknown))
            continue
        row = rows.get(key)
        item = {"key": key, "revision": entry["revision"], "display_name": new.get("display_name") or key,
                "changelog": entry.get("changelog") or [], "template_id": row.id if row else None}
        if row is not None and not row.is_system:
            item.update(kind="conflict", installed_revision=0, template_id=None,
                        message="A custom template already uses {}. Rename or delete it to install the "
                                "MikroWizard template.".format(key))
            out.append(item)
            continue
        if row is None:
            item.update(kind="new", installed_revision=0)
            out.append(item)
            continue
        state = states.get(row.id)
        installed = state.revision if state else 0
        if installed >= entry["revision"] or (state and state.skipped_revision >= entry["revision"]):
            continue
        current = content_of(row)
        cur_hash, new_hash = content_hash(current), content_hash(new)
        known = set(entry.get("previous_hashes") or [])
        if state and state.baseline:
            known.add(content_hash(state.baseline))
        renamed = bool(new.get("display_name")) and new.get("display_name") != row.display_name
        if cur_hash == new_hash:
            kind = "safe" if renamed else "adopt"
        elif cur_hash in known:
            kind = "safe"
        else:
            kind = "review"
        fields = _field_diff(current, new, state, entry)
        if renamed:
            fields.insert(0, {"field": "display_name", "current": row.display_name, "new": new.get("display_name"),
                              "edited": False})
        item.update(kind=kind, installed_revision=installed, fields=fields)
        out.append(item)
    return out


def _is_pro():
    return ISPRO


def _field_diff(current, new, state, entry):
    """Per changed field: current, new, and whether the admin edited it (vs. the baseline, or
    vs. the values MikroWizard shipped in earlier revisions when there is no baseline)."""
    base = state.baseline if state and state.baseline else None
    out = []
    for f in CONTENT_FIELDS:
        if _canon(current.get(f)) == _canon(new.get(f)):
            continue
        if base is not None:
            edited = _canon(current.get(f)) != _canon(base.get(f))
        else:
            edited = not _untouched(entry, f, current.get(f))
        out.append({"field": f, "current": current.get(f), "new": new.get(f), "edited": edited})
    return out


def _merge_field(field, current, new, base, choice):
    if choice == "mine":
        return current
    if choice == "new":
        return new
    if field in DICT_MERGE_FIELDS and isinstance(current, dict) and isinstance(new, dict) and isinstance(base, dict):
        merged = dict(new)
        for k, v in current.items():
            if _canon(v) != _canon(base.get(k)):          # key the admin changed or added: kept
                merged[k] = v
        return merged
    if base is not None and _canon(current) == _canon(base):
        return new                                         # untouched by the admin
    return current


def apply(key, choices=None, user="system"):
    """Apply the newest catalog entry of `key`. choices: {field: 'mine'|'new'} for edited
    fields (default: keep the admin's value). Returns a short result text."""
    catalog, _ = latest()
    entry = next((t for t in (catalog or {}).get("templates") or [] if t["key"] == key), None)
    if entry is None:
        raise CatalogError("{} is not in the catalog".format(key))
    new = entry["content"]
    choices = choices or {}
    unknown = set(new) - set(KNOWN_FIELDS)
    if unknown:
        raise CatalogError("{} needs a newer MikroWizard (fields {})".format(key, ", ".join(sorted(unknown))))
    with _db():
        with database.atomic():
            row = DeviceTemplates.get_or_none(DeviceTemplates.brand == new["brand"], DeviceTemplates.os_type == new["os_type"])
            if row is not None and not row.is_system:
                raise CatalogError("a custom template already uses {}; rename or delete it to install the "
                                   "MikroWizard template".format(key))
            _ensure_brand(new["brand"], entry.get("brand_display_name"))
            if row is None:
                # every field written explicitly (a null stays null; only protocol has a NOT NULL default)
                values = {f: new.get(f) for f in CONTENT_FIELDS if not (f == "protocol" and new.get(f) is None)}
                row = DeviceTemplates.create(
                    brand=new["brand"], os_type=new["os_type"], display_name=new.get("display_name") or key,
                    is_system=True, is_active=True, created=_now(), **values)
                _set_state(row.id, key, entry["revision"], new)
                _history(row.id, key, entry["revision"], snapshot(row), "catalog-new", user)
                return "added"
            state = TemplateCatalogState.get_or_none(TemplateCatalogState.template_id == row.id)
            current = content_of(row)
            base = state.baseline if state and state.baseline else None
            if base is None and content_hash(current) in set(entry.get("previous_hashes") or []):
                base = current                             # unmodified at an older revision
            merged = {}
            for f in CONTENT_FIELDS:
                choice = choices.get(f)
                if choice == "mine":
                    merged[f] = current.get(f)
                elif choice == "new":
                    merged[f] = new.get(f)
                elif base is None:
                    # no baseline: a value MikroWizard shipped before is replaced, an edit is kept
                    merged[f] = new.get(f) if _untouched(entry, f, current.get(f)) else current.get(f)
                else:
                    merged[f] = _merge_field(f, current.get(f), new.get(f), base.get(f), None)
            _history(row.id, key, state.revision if state else 0, snapshot(row), "before-catalog", user)
            for f in CONTENT_FIELDS:
                setattr(row, f, merged.get(f))
            if new.get("display_name"):
                row.display_name = new["display_name"]
            row.save()
            _set_state(row.id, key, entry["revision"], new)
    kept = [f for f in CONTENT_FIELDS if _canon(merged.get(f)) != _canon(new.get(f))]
    return "updated to revision {}{}".format(entry["revision"], " (kept your {})".format(", ".join(kept)) if kept else "")


def apply_safe(user="system"):
    """Apply every 'adopt' / 'safe' / 'new' change. Returns {key: result}."""
    done = {}
    for item in plan():
        if item["kind"] in ("adopt", "safe", "new"):
            try:
                done[item["key"]] = apply(item["key"], user=user)
            except Exception as e:
                done[item["key"]] = "failed: {}".format(e)
                log.warning("template %s not updated: %s", item["key"], e)
    return done


def adopt_unchanged():
    """Record the revision of templates already equal to the catalog (no content change)."""
    for item in plan():
        if item["kind"] == "adopt":
            try:
                apply(item["key"], user="system")
            except Exception as e:
                log.warning("template %s not adopted: %s", item["key"], e)


def skip(key, user="system"):
    catalog, _ = latest()
    entry = next((t for t in (catalog or {}).get("templates") or [] if t["key"] == key), None)
    if entry is None:
        raise CatalogError("{} is not in the catalog".format(key))
    brand, os_type = key.split("/", 1)
    with _db():
        row = DeviceTemplates.get_or_none(DeviceTemplates.brand == brand, DeviceTemplates.os_type == os_type,
                                          DeviceTemplates.is_system == True)  # noqa: E712
        if row is None:
            raise CatalogError("template {} not installed".format(key))
        state = TemplateCatalogState.get_or_none(TemplateCatalogState.template_id == row.id)
        if state is None:
            TemplateCatalogState.create(template_id=row.id, template_key=key, revision=0, baseline=None,
                                        skipped_revision=entry["revision"], updated_at=_now())
        else:
            state.skipped_revision = entry["revision"]
            state.updated_at = _now()
            state.save()


def history(template_id, limit=30):
    with _db():
        q = (TemplateHistory.select().where(TemplateHistory.template_id == template_id)
             .order_by(TemplateHistory.id.desc()).limit(limit))
        return [{"id": h.id, "revision": h.revision, "reason": h.reason, "changed_by": h.changed_by,
                 "changed_at": str(h.changed_at), "content": h.content} for h in q]


def revert(history_id, user="system"):
    with _db():
        with database.atomic():
            h = TemplateHistory.get_by_id(history_id)
            row = DeviceTemplates.get_by_id(h.template_id)
            _history(row.id, h.template_key, None, snapshot(row), "before-revert", user)
            for f in CONTENT_FIELDS:
                setattr(row, f, (h.content or {}).get(f))
            if row.is_system and (h.content or {}).get("display_name"):
                row.display_name = h.content["display_name"]
            row.save()
    return "reverted to the version of {}".format(h.changed_at)


def record_manual_edit(template, user):
    """History entry before an admin edit of a system template (no-op without migration 067)."""
    try:
        if template is None or not getattr(template, "is_system", False) or not available():
            return
        with _db():
            _history(template.id, _key(template.brand, template.os_type), None, snapshot(template), "before-edit", user)
    except Exception as e:
        log.warning("template history not saved: %s", e)


def _history(template_id, key, revision, content, reason, user):
    TemplateHistory.create(template_id=template_id, template_key=key, revision=revision,
                           content=json.loads(_canon(content)), reason=reason, changed_by=str(user or "system"),
                           changed_at=_now())


def _set_state(template_id, key, revision, content):
    TemplateCatalogState.insert(template_id=template_id, template_key=key, revision=revision, baseline=content,
                                skipped_revision=0, updated_at=_now()).on_conflict(
        conflict_target=[TemplateCatalogState.template_id],
        update={TemplateCatalogState.revision: revision, TemplateCatalogState.baseline: content,
                TemplateCatalogState.updated_at: _now()}).execute()


def _ensure_brand(brand, display_name=None):
    """Create a missing brand; a system brand gets the catalog's display name (read-only in the UI)."""
    row = DeviceBrands.get_or_none(DeviceBrands.brand == brand)
    if row is None:
        DeviceBrands.create(brand=brand, display_name=display_name or brand.title(), is_active=True, is_system=True,
                            created=_now())
    elif display_name and getattr(row, "is_system", False) and row.display_name != display_name:
        DeviceBrands.update(display_name=display_name).where(DeviceBrands.brand == brand).execute()


# ---------------------------------------------------------------------------
# periodic check (updater mule)

_last = {"check": 0.0, "bundled": False}


def periodic(params, force=False):
    """Called by the updater mule every hour: bundled catalog once, remote check every
    CHECK_INTERVAL, then auto-apply (mode 'auto') or only record unchanged templates.
    Never raises; returns a status text."""
    if not available():
        return "inactive (migration 067 not run)"
    msg = []
    try:
        if not _last["bundled"]:
            _last["bundled"] = True
            if load_bundled():
                msg.append("bundled catalog stored")
        mode = update_mode()
        if mode != "off" and (force or time.time() - _last["check"] >= CHECK_INTERVAL):
            _last["check"] = time.time()
            try:
                stored, text = fetch_remote(params)
                msg.append(text)
            except CatalogError as e:
                msg.append("check failed: {}".format(e))
                log.warning("template catalog check failed: %s", e)
        adopt_unchanged()
        if mode == "auto":
            done = apply_safe()
            if done:
                msg.append("applied {}".format(", ".join(sorted(done))))
        pending = [p for p in plan() if p["kind"] not in ("adopt", "conflict")]
        if pending:
            msg.append("{} template update(s) pending".format(len(pending)))
    except Exception as e:
        log.exception("template catalog: %s", e)
        msg.append("error: {}".format(e))
    return "; ".join(msg) or "nothing to do"


def status():
    catalog, row = latest()
    items = plan() if catalog else []
    pending = [p for p in items if p["kind"] not in ("adopt", "conflict")]
    return {
        "available": True, "mode": update_mode(), "channel": channel(),
        "catalog_version": catalog["catalog_version"] if catalog else None,
        "catalog_created": catalog.get("created") if catalog else None,
        "origin": row.origin if row else None, "received_at": str(row.received_at) if row else None,
        "pending": len(pending), "pending_review": sum(1 for p in pending if p["kind"] == "review"),
        "conflicts": sum(1 for p in items if p["kind"] == "conflict"),
    }
