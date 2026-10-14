#!/usr/bin/python
# -*- coding: utf-8 -*-

# fw_plan.py: pure decision logic for RouterOS firmware updates (no network, no database)
# MikroWizard.com , Mikrotik router management solution
#
# Based on MikroTik's own documentation / download server (checked 2026-10-11):
#  - File names: v7 "routeros-<ver>-<arch>.npk" (x86/CHR: "routeros-<ver>.npk"),
#    v6 "routeros-<arch>-<ver>.npk" (PowerPC: "routeros-powerpc-<ver>.npk"),
#    extras v7 "<pkg>-<ver>-<arch>.npk" (x86: "<pkg>-<ver>.npk"), zip
#    "all_packages-<arch>-<ver>.zip" (v6 and v7, PowerPC zip uses "ppc").
#    Every file has a "<file>.sha256" next to it ("<hex>  <file name>").
#  - 7.18+: /system/package also lists packages that are only *available* on the server
#    (flag A); they are not installed.
#
# Upgrade path and package set: the free rules below install the target version directly
# with the packages that are installed today. libs/fw_plan_pro.py (Pro) provides the same
# functions with the safe-upgrade rules; firm_lib chooses the rule set.

import re

from libs.check_routeros.routeros_check.helper import RouterOSVersion

ARCHES = ("x86", "arm", "arm64", "mipsbe", "mmips", "ppc", "smips", "tile")

# v6 "routeros-<arch>" bundle members. They show up as separate rows in /system/package on
# v6 but are part of the main package - never uploaded separately.
V6_BUNDLE_MEMBERS = frozenset({
    "system", "ppp", "dhcp", "wireless", "hotspot", "ipv6", "mpls", "routing", "security",
    "advanced-tools", "routerboard",
})
# v6 stand-alone packages whose function is inside the v7 main package (or dropped by v7):
# nothing to upload for them when crossing to v7.
V6_MERGED_OR_DROPPED_IN_V7 = frozenset({"ntp", "lcd", "kvm", "openflow-v6"})


class PlanError(Exception):
    """The update cannot be done safely. Nothing has been changed on the device.

    code       : short machine-readable reason
    permanent  : True when retrying without a configuration change cannot help
    event      : event detail name used for the device event
    """

    def __init__(self, code, message, permanent=True, event="Update Failed", severity="Critical"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.permanent = permanent
        self.event = event
        self.severity = severity


# ---------------------------------------------------------------------------
# Versions / architectures / file names
# ---------------------------------------------------------------------------

def ver(value):
    if isinstance(value, RouterOSVersion):
        return value
    if value is None or str(value).strip() == "":
        raise ValueError("empty version")
    # "7.8 (stable)" as reported by /system/resource
    return RouterOSVersion(str(value).strip().partition(" ")[0])


def vstr(value):
    """Canonical version string ("7.13", "6.49.15", "7.16rc2")."""
    return ver(value).canonical()


def canonical_arch(arch_name):
    """Repository architecture key from /system/resource architecture-name.
    Unknown values return '' (callers must refuse)."""
    a = (arch_name or "").strip().lower()
    if not a:
        return ""
    if "x86" in a or a in ("i386", "i686", "amd64"):
        return "x86"
    if a in ("powerpc", "ppc"):
        return "ppc"
    if a in ARCHES:
        return a
    return ""


def main_package_filename(version, arch):
    v = ver(version)
    vs = v.canonical()
    if v.major <= 6:
        a = "powerpc" if arch == "ppc" else arch
        return "routeros-{}-{}.npk".format(a, vs)
    if arch == "x86":
        return "routeros-{}.npk".format(vs)
    return "routeros-{}-{}.npk".format(vs, arch)


def extra_package_filename(pkg, version, arch):
    """Only v7 publishes extra packages as single files (v6 extras come from the zip)."""
    vs = vstr(version)
    if arch == "x86":
        return "{}-{}.npk".format(pkg, vs)
    return "{}-{}-{}.npk".format(pkg, vs, arch)


def all_packages_filename(version, arch):
    return "all_packages-{}-{}.zip".format(arch, vstr(version))


def repo_architecture_key(arch, pkg=None):
    """Firmware.architecture value used by the repository table."""
    return arch if not pkg else "{}-{}".format(arch, pkg)


def package_name_from_zip_member(member, version):
    """'wireless-7.23.8-arm.npk' / 'wireless-7.23.8.npk' / 'ntp-6.49.23-mipsbe.npk' -> name."""
    base = member.rsplit("/", 1)[-1]
    if not base.endswith(".npk"):
        return None
    marker = "-{}".format(vstr(version))
    if marker not in base:
        return None
    name = base.split(marker)[0]
    return name or None


def parse_sha256_file(text, expected_name=None):
    """'<64 hex>  <file name>' -> hex digest (lower case) or None."""
    if not text:
        return None
    for line in str(text).splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        digest = parts[0].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        if expected_name and len(parts) > 1 and parts[-1].lstrip("*") != expected_name:
            continue
        return digest
    return None


# ---------------------------------------------------------------------------
# Upgrade path (free rules)
# ---------------------------------------------------------------------------

def v6_bridge(old_version_setting=None):
    """No intermediate v6 version in the free rules."""
    return None


def next_step(installed, final, bridge_v6=None, safe_install=True):
    """Next version to install on the way from `installed` to `final` (free rules: `final`
    itself). Returns None when nothing has to be installed (already there or newer:
    downgrades are never done automatically)."""
    installed, final = ver(installed), ver(final)
    if installed >= final:
        return None
    return final


def crosses_wireless_split(installed, step):
    return False


def legacy_wireless_in_use(read_rows):
    return None


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

def _truthy(value):
    return value is True or str(value).lower() in ("true", "yes")


def installed_packages(rows, installed_version):
    """Stand-alone packages actually installed on the device (bundle / main package and
    7.18+ 'available' entries removed).

    Returns {name: {"version": str, "disabled": bool}}.
    """
    v6 = ver(installed_version).major <= 6
    out = {}
    for r in rows or ():
        name = str(r.get("name") or "").strip()
        if not name:
            continue
        if _truthy(r.get("available")):
            continue                      # listed from the update server, not installed
        if name == "routeros" or name.startswith("routeros-"):
            continue                      # main package / v6 bundle
        if v6 and (r.get("bundle") or name in V6_BUNDLE_MEMBERS):
            continue                      # part of the v6 bundle
        out[name] = {"version": str(r.get("version") or ""), "disabled": _truthy(r.get("disabled"))}
    return out


def main_package_version(rows):
    for r in rows or ():
        name = str(r.get("name") or "")
        if (name == "routeros" or name.startswith("routeros-")) and not _truthy(r.get("available")):
            return str(r.get("version") or "")
    return ""


def _package_set(installed_version, rows):
    """Enabled stand-alone packages and a note about the disabled ones."""
    pkgs = installed_packages(rows, installed_version)
    enabled = {n: p for n, p in pkgs.items() if not p["disabled"]}
    notes = []
    if any(p["disabled"] for p in pkgs.values()):
        notes.append("disabled packages left as they are: " +
                     ", ".join(sorted(n for n, p in pkgs.items() if p["disabled"])))
    return enabled, notes


def _new_selected(selection, installed_version, step, rows):
    """Selected packages that are not installed yet: installed additionally. Names that
    are part of the main package (v6 bundle members, the main package itself) are skipped."""
    if not selection:
        return set()
    installed = set(installed_packages(rows, installed_version))
    new = set()
    for name in selection:
        name = str(name or "").strip()
        if not name or name in installed or name == "routeros" or name.startswith("routeros-"):
            continue
        if ver(step).major <= 6 and name in V6_BUNDLE_MEMBERS:
            continue
        new.add(name)
    return new


def _packages_only(installed_version, enabled, selection, notes, rows=None):
    main_ver = installed_version.canonical()
    extras = {n for n, p in enabled.items() if p["version"] and p["version"] != main_ver}
    if selection is not None:
        sel = set(selection)
        extras |= (sel & set(enabled)) | _new_selected(sel, installed_version, installed_version, rows)
    return False, sorted(extras), notes


def _drop_merged_v6(extras, notes):
    """v6 -> v7: packages included in the v7 main package (or dropped) are not uploaded."""
    dropped = sorted(extras & V6_MERGED_OR_DROPPED_IN_V7)
    if dropped:
        notes.append("v6 packages included in RouterOS v7: " + ", ".join(dropped))
    return extras - V6_MERGED_OR_DROPPED_IN_V7


def left_behind_packages(enabled, extras):
    """Enabled packages that are not updated: RouterOS disables a package whose version
    differs from the main package after the reboot."""
    return sorted(set(enabled) - set(extras))


def _left_behind_note(enabled, extras, notes):
    left = left_behind_packages(enabled, extras)
    if left:
        notes.append("firmware only: package(s) {} stay on the old version and will be disabled by "
                     "RouterOS after the reboot".format(", ".join(left)))


def required_packages(installed_version, step, arch, rows, mode="full", selection=None,
                      legacy_wireless_in_use=None, rb_model="", board_name=""):
    """Packages uploaded together with the main package.

    mode: 'full'          main package + every enabled extra package (RouterOS disables a
                          package left on the old version) + selected packages that are not
                          installed yet (installed additionally)
          'firmware_only' main package only - enabled extras stay on the old version and are
                          disabled by RouterOS after the reboot (noted)
          'packages_only' no main upgrade: enabled extras whose version differs from the
                          main package are re-installed at the main package version, plus the
                          selected packages (installed additionally when missing)

    Returns (main: bool, extras: sorted list of package names, notes: list of str).
    Raises PlanError when the set cannot be built safely.
    """
    installed_version, step = ver(installed_version), ver(step)
    enabled, notes = _package_set(installed_version, rows)
    if mode == "packages_only":
        return _packages_only(installed_version, enabled, selection, notes, rows)
    if mode == "firmware_only":
        extras = set()
    else:
        extras = set(enabled) | _new_selected(selection, installed_version, step, rows)
    crossing_v7 = installed_version.major <= 6 and step.major >= 7
    if crossing_v7:
        extras = _drop_merged_v6(extras, notes)
    if mode == "firmware_only":
        kept = set(enabled) - V6_MERGED_OR_DROPPED_IN_V7 if crossing_v7 else set(enabled)
        _left_behind_note(kept, extras, notes)
    return True, sorted(extras), notes


def native_expected_packages(packages_before, packages_after):
    """Packages that must still be active after a native (/system/package/update) update."""
    return set(packages_before or ()) - V6_MERGED_OR_DROPPED_IN_V7 - {"wifiwave2"}


# ---------------------------------------------------------------------------
# Device files
# ---------------------------------------------------------------------------

OWN_FILE_PREFIX = "mw-"


def own_file_name(repo_arch_key, version):
    """Name used on the device for a package uploaded by MikroWizard."""
    return "{}{}-{}.npk".format(OWN_FILE_PREFIX, vstr(version), repo_arch_key)


def _base_name(name):
    return str(name or "").replace("\\", "/").rsplit("/", 1)[-1]


def is_package_file(row):
    name = str(row.get("name") or "")
    return name.lower().endswith(".npk") or str(row.get("type") or "") == "package"


def is_own_file(name):
    """Files written by MikroWizard: 'mw-*.npk' and the names older versions used
    ('<arch>.npk', '<arch>-<pkg>.npk')."""
    base = _base_name(name)
    if not base.lower().endswith(".npk"):
        return False
    if base.startswith(OWN_FILE_PREFIX):
        return True
    stem = base[:-4]
    return stem in ARCHES or any(stem.startswith(a + "-") for a in ARCHES) and not re.search(r"\d+\.\d+", stem)


def classify_device_files(file_rows):
    """Package files present on the device: (own, foreign) lists of /file rows.
    Every .npk in the root folder is installed by RouterOS at the next reboot."""
    own, foreign = [], []
    for row in file_rows or ():
        if not is_package_file(row):
            continue
        name = str(row.get("name") or "")
        parts = name.strip("/").split("/")
        if len(parts) == 1:
            (own if is_own_file(name) else foreign).append(row)
        elif len(parts) == 2 and parts[0] == "flash" and is_own_file(name):
            own.append(row)            # left there by an older MikroWizard version
    return own, foreign


# /file shows what RouterOS itself read from an uploaded package (recorded on CHR 7.17:
# type=package, package-name=system, package-version=7.24.5, package-architecture=i386).
_PKG_ARCH = {"i386": "x86", "x86_64": "x86", "x86": "x86", "powerpc": "ppc", "ppc": "ppc"}
MAIN_PACKAGE_NAMES = ("system", "routeros")


def check_uploaded_package(row, version, arch, pkg=None, router_major=7):
    """Error text when the router does not see the uploaded file as the expected package,
    None when it matches. Fields the router does not report (older RouterOS) are skipped;
    v7 must report type=package."""
    if router_major >= 7 and str(row.get("type") or "") != "package":
        return "not recognised as a RouterOS package by the router (type {!r})".format(row.get("type"))
    pv = row.get("package-version")
    if pv not in (None, ""):
        try:
            if ver(pv) != ver(version):
                return "package version {} != expected {}".format(pv, vstr(version))
        except ValueError:
            return "unreadable package version {!r}".format(pv)
    pa = row.get("package-architecture")
    if pa not in (None, ""):
        got = _PKG_ARCH.get(str(pa).lower(), str(pa).lower())
        if got != arch:
            return "package architecture {} != router {}".format(pa, arch)
    pn = row.get("package-name")
    if pn not in (None, ""):
        if pkg is None and pn not in MAIN_PACKAGE_NAMES:
            return "package {} is not the RouterOS main package".format(pn)
        if pkg is not None and pn != pkg:
            return "package {} != expected {}".format(pn, pkg)
    return None


def find_file(file_rows, name):
    for row in file_rows or ():
        n = str(row.get("name") or "").strip("/")
        if n == name or n == "flash/" + name:
            return row
    return None


# ---------------------------------------------------------------------------
# Durations
# ---------------------------------------------------------------------------

_DUR_V6 = re.compile(r"(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d{2}):(\d{2})")
_DUR_V7 = re.compile(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?(?:(\d+)ms)?")


def parse_uptime(value):
    """RouterOS uptime -> seconds. Handles v7 '1w2d3h4m5s' and v6 '1w2d03:04:05'.
    Returns None when it cannot be parsed."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    if not s:
        return None
    m = _DUR_V6.fullmatch(s)
    if m:
        w, d, h, mi, se = (int(x or 0) for x in m.groups())
        return w * 604800 + d * 86400 + h * 3600 + mi * 60 + se
    m = _DUR_V7.fullmatch(s)
    if m and any(m.groups()):
        w, d, h, mi, se, _ms = (int(x or 0) for x in m.groups())
        return w * 604800 + d * 86400 + h * 3600 + mi * 60 + se
    return None
