#!/usr/bin/python
# -*- coding: utf-8 -*-

# traffic_math.py: pure, dependency-free helpers for the data poller traffic pipeline.
# MikroWizard.com , Mikrotik router management solution
#
# Everything in this module is side-effect free (no DB, no Redis, no RouterOS I/O)
# so it can be unit-tested for every RouterOS model / interface layout without a lab.

import re

# ---------------------------------------------------------------------------
# Sensor classification
# ---------------------------------------------------------------------------

# Prefixes of per-interface / per-device rate sensors written by the poller.
RATE_SENSOR_PREFIXES = ("rx-", "tx-", "rxp-", "txp-")
TOTAL_SENSORS = ("rx-total", "tx-total", "rxp-total", "txp-total")


def is_rate_sensor(name):
    """True for traffic rate sensors (rx-/tx-/rxp-/txp-<iface>).

    Uses a strict prefix match so derived keys such as
    'radio-AABBCC-rx-ccq' or 'radio-AABBCC-tx-ccq' are NOT treated as traffic.
    """
    return isinstance(name, str) and name.startswith(RATE_SENSOR_PREFIXES)


def offline_zero_sensors(sensors):
    """Return the sensor keys that should be written as 0 while a device is offline.

    Only traffic rate sensors are zeroed (cpu/memory/health/radio values are left
    as gaps - a 0 there would be a false reading). Always includes the 4 totals.
    """
    out = set(TOTAL_SENSORS)
    for s in sensors or ():
        # Skip legacy dynamic-tunnel sensors (e.g. 'rx-<pppoe-user>') left in dev.sensors
        # by older versions - writing zeros to thousands of dead keys every minute is waste.
        if is_rate_sensor(s) and "<" not in s:
            out.add(s)
    return sorted(out)


# ---------------------------------------------------------------------------
# Interface classification & device totals
# ---------------------------------------------------------------------------

# RouterOS `type` values of interfaces that carry real wire / radio traffic.
# SFP / SFP+ / QSFP ports report type 'ether' on RouterOS.
PHYSICAL_TYPES = frozenset({
    "ether", "wlan", "wifi", "wifiwave2", "w60g", "lte", "5g", "modem",
})

# Logical containers whose counters duplicate the member ports.
CONTAINER_TYPES = frozenset({"bridge", "bond", "bonding"})

DYNAMIC_NAME_PREFIXES = ("<pppoe-", "<l2tp-", "<sstp-", "<ovpn-", "<ppp-", "<pptp-")


def _truthy(v):
    return v in (True, "true", "yes", "True")


def is_dynamic_interface(name, iface):
    """Dynamic client tunnels (PPPoE/L2TP/SSTP/OVPN server sessions etc.)."""
    name = name or ""
    return (
        _truthy((iface or {}).get("dynamic"))
        or name.startswith(DYNAMIC_NAME_PREFIXES)
        or "<" in name
    )


def is_loopback_interface(name, iface):
    lname = (name or "").lower()
    return lname in ("lo", "loopback") or "loopback" in lname or (iface or {}).get("type") == "loopback"


def _rates(iface):
    return (
        iface.get("rx-bits-per-second", 0) or 0,
        iface.get("tx-bits-per-second", 0) or 0,
        iface.get("rx-packets-per-second", 0) or 0,
        iface.get("tx-packets-per-second", 0) or 0,
    )


def compute_device_totals(interfaces):
    """Compute device wire totals (rx/tx bps, rx/tx pps) without double counting.

    Rule:
      * If the device has physical ports: sum every enabled, non-dynamic physical
        port (ether/wlan/wifi/w60g/lte...). Bridge and bond *members* (slaves) ARE
        counted - they are the real wire. The bridge/bond/vlan/tunnel interfaces
        themselves are never counted, because their counters duplicate the members.
      * If the device has no physical ports (VPN-only CHR, etc.): sum every enabled,
        non-dynamic, non-slave, non-container, non-loopback interface.

    Each packet is counted once on ingress (rx) and once on egress (tx), so routed
    traffic WAN->LAN is not double counted inside rx-total or tx-total.

    Returns dict with keys rx-total, tx-total, rxp-total, txp-total.
    """
    totals = {"rx-total": 0, "tx-total": 0, "rxp-total": 0, "txp-total": 0}
    if not interfaces:
        return totals

    has_physical = any(
        (iface or {}).get("type") in PHYSICAL_TYPES
        and not is_dynamic_interface(name, iface)
        for name, iface in interfaces.items()
    )

    for name, iface in interfaces.items():
        iface = iface or {}
        if _truthy(iface.get("disabled")):
            continue
        if is_dynamic_interface(name, iface) or is_loopback_interface(name, iface):
            continue
        itype = iface.get("type", "")
        if has_physical:
            if itype not in PHYSICAL_TYPES:
                continue
        else:
            if itype in CONTAINER_TYPES or _truthy(iface.get("slave")):
                continue
        rx, tx, rxp, txp = _rates(iface)
        totals["rx-total"] += rx
        totals["tx-total"] += tx
        totals["rxp-total"] += rxp
        totals["txp-total"] += txp
    return totals


# ---------------------------------------------------------------------------
# Counter based rate engine
# ---------------------------------------------------------------------------

MAX_RATE_INTERVAL = 300  # seconds; older baselines are discarded (no spikes after outages)
COUNTER_KEYS = ("rx-byte", "tx-byte", "rx-packet", "tx-packet")


def _counter(iface, key):
    v = iface.get(key)
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def compute_interface_rates(prev_counters, interfaces, now):
    """Compute 60s-average bps/pps from cumulative counters.

    prev_counters: {name: [ts, rx_byte, tx_byte, rx_packet, tx_packet]} from the previous poll.
    interfaces:    {name: iface_dict} as returned by /interface/print stats.
    now:           current unix time (float).

    Mutates interfaces in place, setting rx/tx-bits-per-second and rx/tx-packets-per-second
    for every interface with a valid baseline.

    Returns (new_counters, valid_names):
      new_counters  baseline to store for the next poll (only interfaces with counters)
      valid_names   set of interface names whose rates came from counters this poll.
                    Interfaces NOT in this set (cold start, missing counters, counter reset,
                    stale baseline) need a fallback source (monitor-traffic).
    """
    prev_counters = prev_counters or {}
    new_counters = {}
    valid = set()
    for name, iface in (interfaces or {}).items():
        vals = [_counter(iface, k) for k in COUNTER_KEYS]
        if vals[0] is None or vals[1] is None:
            # No byte counters (old RouterOS without stats, or odd interface type).
            continue
        vals = [v if v is not None else 0 for v in vals]
        new_counters[name] = [now] + vals

        prev = prev_counters.get(name)
        if not prev or len(prev) < 5:
            continue
        try:
            p_ts, p_rx, p_tx, p_rxp, p_txp = float(prev[0]), int(prev[1]), int(prev[2]), int(prev[3]), int(prev[4])
        except (TypeError, ValueError):
            continue
        dt = now - p_ts
        if not (0 < dt <= MAX_RATE_INTERVAL):
            continue
        d = (vals[0] - p_rx, vals[1] - p_tx, vals[2] - p_rxp, vals[3] - p_txp)
        if d[0] < 0 or d[1] < 0:
            # Counter reset (reboot / interface re-created / wrap): re-baseline, no rate this poll.
            continue
        iface["rx-bits-per-second"] = int(round(d[0] * 8 / dt))
        iface["tx-bits-per-second"] = int(round(d[1] * 8 / dt))
        iface["rx-packets-per-second"] = int(round(max(d[2], 0) / dt))
        iface["tx-packets-per-second"] = int(round(max(d[3], 0) / dt))
        valid.add(name)
    return new_counters, valid


def monitor_traffic_candidates(interfaces, valid_names):
    """Interfaces that still need an instantaneous rate from /interface/monitor-traffic.

    Only interfaces without a counter-based rate this poll, and never dynamic tunnels or
    names that would break the comma separated RouterOS argument.
    """
    out = []
    for name, iface in (interfaces or {}).items():
        if not name or name in valid_names or name == "aggregate":
            continue
        if "," in name or is_dynamic_interface(name, iface):
            continue
        if _truthy((iface or {}).get("disabled")):
            continue
        out.append(name)
    return out


# ---------------------------------------------------------------------------
# Time-series grid alignment for charts
# ---------------------------------------------------------------------------

DELTA_STEP_MS = {"live": 60000, "5m": 300000, "1h": 3600000, "daily": 86400000}
MAX_GRID_POINTS = 20000


def align_timeseries_grid(raw_points, start_ms, end_ms, step_ms, fill_value=0.0, open_bucket=True):
    """Place samples on a regular grid of `step_ms` slots.

    * Samples are assigned to floor(ts / step) slots, matching Redis compaction buckets.
    * A single empty slot between two filled slots is treated as poll jitter (the poll
      period is ~60-75s, so a 60s slot is occasionally skipped) and gets the previous
      value instead of a false drop to zero.
    * Runs of 2+ empty slots are a real gap (device or poller down) and get fill_value.
    * If open_bucket is True the last slot is still being filled; it is dropped when empty
      so charts don't end with a fake zero.
    * Very large ranges (more than MAX_GRID_POINTS slots) are returned raw to protect CPU.
    """
    if not step_ms or step_ms <= 0:
        step_ms = 60000
    points = [(int(p[0]), p[1]) for p in (raw_points or []) if p and len(p) >= 2]
    first_slot = (int(start_ms) // step_ms) * step_ms
    last_slot = (int(end_ms) // step_ms) * step_ms
    if last_slot < first_slot:
        return sorted(points)
    if (last_slot - first_slot) // step_ms + 1 > MAX_GRID_POINTS:
        return sorted(points)

    filled = {}
    for ts, val in points:
        slot = (ts // step_ms) * step_ms
        if first_slot <= slot <= last_slot:
            filled[slot] = val  # last sample in a slot wins (duplicate_policy=last semantics)

    slots = list(range(first_slot, last_slot + step_ms, step_ms))
    if open_bucket and slots and slots[-1] not in filled:
        slots = slots[:-1]

    out = []
    n = len(slots)
    for i, s in enumerate(slots):
        if s in filled:
            out.append((s, filled[s]))
            continue
        prev_filled = i > 0 and slots[i - 1] in filled
        next_filled = i + 1 < n and slots[i + 1] in filled
        if prev_filled and next_filled:
            out.append((s, filled[slots[i - 1]]))  # single-slot jitter gap
        else:
            out.append((s, fill_value))
    return out


# ---------------------------------------------------------------------------
# Uptime / reboot helpers
# ---------------------------------------------------------------------------

def parse_routeros_uptime(val):
    """Parse RouterOS uptime string into total integer seconds.
    Handles: '45s', '5m12s', '6h34m57s', '1d04:12:00', '3w2d05:10:00', '04:12:00', '1w2d3h4m5s'.
    """
    if not val or not isinstance(val, str):
        return 0
    val = val.strip().lower()
    total = 0
    m = re.search(r'(\d+)\s*w', val)
    if m:
        total += int(m.group(1)) * 7 * 86400
    m = re.search(r'(\d+)\s*d', val)
    if m:
        total += int(m.group(1)) * 86400
    colon = re.search(r'(\d+):(\d+):(\d+)', val)
    if colon:
        total += int(colon.group(1)) * 3600 + int(colon.group(2)) * 60 + int(colon.group(3))
    else:
        m = re.search(r'(\d+)\s*h', val)
        if m:
            total += int(m.group(1)) * 3600
        m = re.search(r'(\d+)\s*m(?!s)', val)
        if m:
            total += int(m.group(1)) * 60
        m = re.search(r'(\d+)\s*s', val)
        if m:
            total += int(m.group(1))
    return total


REBOOT_KEYWORDS = ("reboot", "shutdown", "power failure", "power outage", "kernel failure",
                   "overtemperature", "watchdog")


def pick_reboot_reason(log_entries, default):
    """Pick the newest system log line that explains a reboot.

    log_entries: iterable of dicts with 'message' and optional 'topics' in RouterOS order
                 (oldest first). Topics like 'system,error,critical' or 'system,info' match.
    """
    entries = list(log_entries or [])
    for entry in reversed(entries):
        topics = str(entry.get("topics", "system"))
        if "system" not in topics:
            continue
        msg = str(entry.get("message", ""))
        if any(w in msg.lower() for w in REBOOT_KEYWORDS):
            return msg
    return default
