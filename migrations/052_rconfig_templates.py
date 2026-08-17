# 052_rconfig_templates.py
# Seeds ALL system templates (base + rConfig community) and brands for BOTH
# free and pro tiers, plus the PAM device_connections columns that non-MikroTik
# device management depends on (agent_modes, privileged_credential_id).
# Adds is_system column to device_brands if not present.
# Idempotent — safe to run on already-migrated installations.

import json
import logging

log = logging.getLogger("migration_052_rconfig")

def _sql_str(v):
    if v is None:
        return "NULL"
    s = json.dumps(v)
    s = s.replace("'", "''")
    s = s.replace("%", "%%")
    return "'{}'::jsonb".format(s)

# -------------------------------------------------------------------------
# Vendor-specific command dictionaries
# -------------------------------------------------------------------------

CISCO_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
CISCO_ERRORS = {"patterns": ["% Invalid", "% Ambiguous", "Error"]}
CISCO_PAGINATION = {"enabled": True, "pattern": "--More--", "key": "space"}

HP_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
HP_ERRORS = {"patterns": ["Invalid input", "Error", "Unrecognized"]}
HP_PAGINATION = {"enabled": True, "pattern": "--More--", "key": "space"}

DELL_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
DELL_ERRORS = {"patterns": ["% Invalid", "% Error"]}

FORTINET_CMDS = {
    "show_config": "show full-configuration", "show_interfaces": "get system interface",
    "show_routing": "get router info routing-table all", "show_arp": "get system arp",
    "show_version": "get system status", "show_log": "get log event",
}
FORTINET_ERRORS = {"patterns": ["command parse error", "unrecognized", "Error"]}
FORTINET_PAGINATION = {"enabled": True, "pattern": "--More--", "key": "space"}

PANOS_CMDS = {
    "show_config": "show config running", "show_interfaces": "show interfaces all",
    "show_routing": "show route", "show_arp": "show arp all",
    "show_version": "show system info", "show_log": "show log system",
}
PANOS_ERRORS = {"patterns": ["Syntax error", "Invalid command", "Error"]}

JUNIPER_CMDS = {
    "show_config": "show configuration", "show_interfaces": "show interfaces terse",
    "show_routing": "show route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show log messages | last 50",
}
JUNIPER_ERRORS = {"patterns": ["error:", "syntax error", "unknown command"]}
JUNIPER_PAGINATION = {"enabled": True, "pattern": r"---\(more( \d+%)?\)---", "key": "space"}

MIKROTIK_CMDS = {
    "show_config": "/export terse", "show_interfaces": "/interface print",
    "show_routing": "/ip route print", "show_arp": "/ip arp print",
    "show_version": ":put [/system resource get version]", "show_log": "/log print",
}
MIKROTIK_ERRORS = {"patterns": ["bad command", "no such item", "syntax error"]}

BROCADE_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
BROCADE_ERRORS = {"patterns": ["Invalid", "Error", "Unrecognized command"]}
BROCADE_PAGINATION = {"enabled": True, "pattern": "--More--", "key": "space"}

CHECKPOINT_CMDS = {
    "show_config": "show configuration", "show_interfaces": "show interfaces",
    "show_routing": "show route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show log",
}
CHECKPOINT_ERRORS = {"patterns": ["Error", "Invalid"]}

CIENA_TL1_CMDS = {
    "show_config": "RTRV-CONFIG", "show_interfaces": "RTRV-EQPT",
    "show_routing": "RTRV-RTE", "show_version": "RTRV-INV",
}
CIENA_TL1_ERRORS = {"patterns": ["DENY"]}

RUCKUS_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
RUCKUS_ERRORS = {"patterns": ["Invalid", "Error"]}
RUCKUS_PAGINATION = {"enabled": True, "pattern": "--More--", "key": "space"}

SONICWALL_CMDS = {
    "show_config": "show config running", "show_interfaces": "show interfaces",
    "show_routing": "show route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show log",
}
SONICWALL_ERRORS = {"patterns": ["Error", "Invalid"]}

AVAYA_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
AVAYA_ERRORS = {"patterns": ["Invalid", "Error"]}

GENERIC_CMDS = {
    "show_config": "show running-config", "show_interfaces": "show interfaces",
    "show_routing": "show ip route", "show_arp": "show arp",
    "show_version": "show version", "show_log": "show logging",
}
GENERIC_ERRORS = {"patterns": ["Error", "Invalid", "Unrecognized"]}

# -------------------------------------------------------------------------
# Template factory helper — keeps each template entry compact (5-8 lines)
# -------------------------------------------------------------------------

def _t(brand, os_type, display_name, connection, prompt,
       privilege_escalation, commands, pagination, error_patterns,
       post_login_commands, pre_logout_commands):
    return {
        "brand": brand, "os_type": os_type, "display_name": display_name,
        "connection": connection, "prompt": prompt,
        "privilege_escalation": privilege_escalation,
        "commands": commands, "pagination": pagination,
        "error_patterns": error_patterns,
        "post_login_commands": post_login_commands,
        "pre_logout_commands": pre_logout_commands,
    }

# -------------------------------------------------------------------------
# Shared connection/prompt patterns used across many templates
# -------------------------------------------------------------------------

SSH = lambda port=22, timeout=30: {"default_port_ssh": port, "default_port_telnet": 23, "timeout": timeout, "protocols": ["ssh", "telnet"]}
TELNET = lambda port=23, timeout=30: {"default_port_ssh": 22, "default_port_telnet": port, "timeout": timeout, "protocols": ["telnet"]}
SSH_ONLY = lambda port=22, timeout=30: {"default_port_ssh": port, "default_port_telnet": 23, "timeout": timeout, "protocols": ["ssh"]}

PROMPT_UP = lambda login="Username:", passwd="Password:", patterns=None: {
    "patterns": patterns or [r"\S+#\s*$", r"\S+>\s*$"],
    "login_pattern": login, "password_pattern": passwd,
}
PROMPT_LOGIN = lambda login="login:", passwd="Password:", patterns=None: {
    "patterns": patterns or [r"\S+#\s*$", r"\S+>\s*$"],
    "login_pattern": login, "password_pattern": passwd,
}

PRIV_ENABLE = lambda cmd="enable", prompt=r"\S+#", pwd_prompt=r"[Pp]assword:?": {
    "command": cmd, "password_prompt": pwd_prompt, "success_pattern": prompt
}

# -------------------------------------------------------------------------
# Base brands (previously seeded only by the PRO migration) — required by the
# non-MikroTik device/template feature in both tiers.
# -------------------------------------------------------------------------

BASE_BRANDS = [
    ("cisco", "Cisco"),
    ("huawei", "Huawei"),
    ("zte", "ZTE"),
    ("juniper", "Juniper"),
    ("linux", "Linux"),
    ("darwin", "macOS"),
    ("freebsd", "FreeBSD"),
    ("windows", "Windows"),
    ("generic", "Generic"),
    ("fortinet", "Fortinet"),
]

# -------------------------------------------------------------------------
# Base system templates (previously seeded only by the PRO migration).
# privilege_escalation uses the canonical schema:
#   {command, password_prompt, success_pattern}
# -------------------------------------------------------------------------

BASE_TEMPLATES = [
    _t("cisco", "ios", "Cisco IOS",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r"\S+#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       PRIV_ENABLE(),
       {"show_config": "show running-config", "show_interfaces": "show interfaces brief",
        "show_routing": "show ip route", "show_arp": "show arp",
        "show_version": "show version", "show_log": "show logging"},
       {"enabled": True, "pattern": "--More--", "key": "space"},
       {"patterns": ["% Invalid", "% Ambiguous", "Error"]},
       ["terminal length 0"], ["exit"]),

    _t("cisco", "nxos", "Cisco NX-OS",
       {"default_port_ssh": 22, "timeout": 30, "protocols": ["ssh"]},
       {"patterns": [r"\S+#\s*$"], "login_pattern": r"login:", "password_pattern": r"Password:"},
       None,
       {"show_config": "show running-config", "show_interfaces": "show interface brief",
        "show_routing": "show ip route", "show_arp": "show ip arp",
        "show_version": "show version", "show_log": "show logging last 50"},
       {"enabled": True, "pattern": "--More--", "key": "space"},
       {"patterns": ["% Invalid", "% Ambiguous", "Error"]},
       ["terminal length 0"], ["exit"]),

    _t("cisco", "asa", "Cisco ASA",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r"\S+#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       PRIV_ENABLE(),
       {"show_config": "show running-config", "show_interfaces": "show interface ip brief",
        "show_routing": "show route", "show_arp": "show arp",
        "show_version": "show version", "show_log": "show logging"},
       {"enabled": True, "pattern": "<--- More --->", "key": "space"},
       {"patterns": ["% Invalid", "% Ambiguous", "Error"]},
       ["terminal pager 0"], ["exit"]),

    _t("huawei", "vrp", "Huawei VRP",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r"\<[\w\-]+\>", r"\[[\w\-]+\]"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       {"command": "system-view", "password_prompt": "", "success_pattern": r"\[\S+\]"},
       {"show_config": "display current-configuration", "show_interfaces": "display interface brief",
        "show_routing": "display ip routing-table", "show_arp": "display arp all",
        "show_version": "display version", "show_log": "display logbuffer"},
       {"enabled": True, "pattern": "---- More ----", "key": "space"},
       {"patterns": ["Error:", "Unrecognized", "Incomplete"]},
       ["screen-length 0 temporary"], ["return", "quit"]),

    _t("zte", "zxr10", "ZTE ZXR10",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r"\S+#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       PRIV_ENABLE(),
       {"show_config": "show running-config", "show_interfaces": "show interface brief",
        "show_routing": "show ip route", "show_arp": "show arp",
        "show_version": "show version", "show_log": "show log"},
       {"enabled": True, "pattern": "--More--", "key": "space"},
       {"patterns": ["% Invalid", "% Unrecognized"]},
       ["terminal length 0"], ["exit"]),

    _t("juniper", "junos", "Juniper JunOS",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login:", "password_pattern": r"Password:"},
       {"command": "configure", "password_prompt": "", "success_pattern": r"\S+@\S+#"},
       {"show_config": "show configuration", "show_interfaces": "show interfaces terse",
        "show_routing": "show route", "show_arp": "show arp",
        "show_version": "show version", "show_log": "show log messages | last 50"},
       {"enabled": True, "pattern": r"---\(more( \d+%)?\)---", "key": "space"},
       {"patterns": ["error:", "syntax error", "unknown command"]},
       ["set cli screen-length 0"], ["exit"]),

    _t("linux", "generic", "Linux (Generic)",
       {"default_port_ssh": 22, "timeout": 30, "protocols": ["ssh"]},
       {"patterns": [r"\$\s*$", r"#\s*$"], "login_pattern": r"login:", "password_pattern": r"Password:"},
       PRIV_ENABLE(cmd="sudo -i", prompt=r"#\s*$"),
       {"show_config": "cat /etc/network/interfaces 2>/dev/null || cat /etc/networks 2>/dev/null || echo no-config",
        "show_interfaces": "ip addr show", "show_routing": "ip route show", "show_arp": "arp -n",
        "show_version": "uname -a", "show_log": "journalctl -n 50 --no-pager 2>/dev/null || dmesg | tail -50"},
       {"enabled": False},
       {"patterns": ["command not found", "No such file"]},
       [], ["exit"]),

    _t("generic", "generic", "Generic Device",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh", "telnet"]},
       {"patterns": [r">\s*$", r"#\s*$", r"\$\s*$"], "login_pattern": r"(?:login|Username).*:", "password_pattern": r"Password:"},
       None,
       {},
       {"enabled": False},
       {"patterns": ["Error", "Invalid", "Unrecognized"]},
       [], ["exit"]),
]

# -------------------------------------------------------------------------
# ALL RCONFIG TEMPLATES (organized by vendor)
# -------------------------------------------------------------------------

RCONFIG_TEMPLATES = [
    # ---- Cisco (8 templates) ----
    _t("cisco", "ios-ssh-enable", "Cisco IOS - SSH - Enable",
       SSH(), PROMPT_UP(), PRIV_ENABLE(),
       CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("cisco", "ios-ssh-noenable", "Cisco IOS - SSH - No Enable",
       SSH(timeout=60), PROMPT_UP(), None,
       CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("cisco", "ios-telnet-enable", "Cisco IOS - Telnet - Enable",
       TELNET(), PROMPT_UP(), PRIV_ENABLE(),
       CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("cisco", "ios-telnet-noenable", "Cisco IOS - Telnet - No Enable",
       TELNET(), PROMPT_UP(), None,
       CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("cisco", "ios-telnet-enable-nouser", "Cisco IOS - Telnet - Enable - No Username",
       TELNET(), {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": None, "password_pattern": r"Password:"},
       PRIV_ENABLE(), CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("cisco", "asa-ssh-enable", "Cisco ASA - SSH - Enable",
       SSH(), PROMPT_UP(), PRIV_ENABLE(),
       CISCO_CMDS, {"enabled": True, "pattern": "<--- More --->", "key": "space"}, CISCO_ERRORS,
       ["terminal pager 0"], ["quit"]),

    _t("cisco", "wlc-ssh", "Cisco WLC - SSH",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 30, "protocols": ["ssh"], "ssh_interactive": True},
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"User:", "password_pattern": r"Password:"},
       None, CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["config paging disable"], ["logout"]),

    _t("cisco", "smb-telnet", "Cisco SMB - Telnet - No Enable",
       TELNET(),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"User Name:", "password_pattern": r"Password"},
       None, CISCO_CMDS, CISCO_PAGINATION, CISCO_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- HP / ProCurve (7 templates) ----
    _t("hp", "procurve-ssh", "HP ProCurve - SSH - No Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "no page"], ["quit"]),

    _t("hp", "procurve-ssh-v2", "HP ProCurve - SSH - No Enable v2",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "nno page"], ["quit"]),

    _t("hp", "procurve-telnet", "HP ProCurve - Telnet - No Enable",
       TELNET(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "no page"], ["quit"]),

    _t("hp", "flexfabric-ssh", "HP FlexFabric - SSH - No Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "screen-length disable"], ["quit"]),

    _t("hp", "1920-ssh", "HP 1920 - SSH - No Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(),
       {"command": "_cmdline-mode on \n y", "password_prompt": "", "success_pattern": r"\S+#"},
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "screen-length disable"], ["quit"]),

    _t("hp", "h3c-ssh", "H3C - SSH - No Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["screen-length disable"], ["quit"]),

    _t("hp", "a5120-ssh", "HP A5120 - SSH - No System View",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["screen-length disable"], ["quit"]),

    # ---- Dell (3 templates) ----
    _t("dell", "s4048-ssh", "Dell S4048 - SSH - No Enable",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"Login:", "password_pattern": r"Password:"},
       None, DELL_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, DELL_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("dell", "5524-telnet", "Dell 5524 - Telnet - No Enable",
       TELNET(timeout=5),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"User:", "password_pattern": r"Password:"},
       None, DELL_CMDS, {"enabled": False}, DELL_ERRORS,
       ["terminal datadump"], ["quit"]),

    _t("dell", "6248-telnet", "Dell 6248P - Telnet - Enable",
       TELNET(timeout=5),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"User:", "password_pattern": r"Password:"},
       PRIV_ENABLE(), DELL_CMDS, {"enabled": False}, DELL_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- Aruba (3 templates) ----
    _t("aruba", "2930f-ssh", "Aruba 2930F - SSH - No Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(), None,
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["Press any key to continue", "nno page"], ["quit"]),

    _t("aruba", "s3500-ssh", "Aruba S3500 - SSH - Enable",
       SSH_ONLY(timeout=5), PROMPT_UP(), PRIV_ENABLE(),
       HP_CMDS, HP_PAGINATION, HP_ERRORS,
       ["no paging"], ["exit"]),

    # ---- Fortinet (4 templates) ----
    _t("fortinet", "non-vdom", "FortiGate - SSH - Non-VDOM",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+\s*#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, FORTINET_CMDS, FORTINET_PAGINATION, FORTINET_ERRORS,
       ["config system console\n set output standard\n end"], ["quit\n"]),

    _t("fortinet", "vdom", "FortiGate - SSH - VDOM",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+\s*#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, FORTINET_CMDS, FORTINET_PAGINATION, FORTINET_ERRORS,
       ["config global\nconfig system console\n set output standard\n end\n end"], ["quit\n"]),

    _t("fortinet", "noninteractive", "FortiGate - SSH - NonInteractive",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 5, "protocols": ["ssh"], "is_non_interactive": True},
       {"patterns": [r"\S+\s*#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, FORTINET_CMDS, FORTINET_PAGINATION, FORTINET_ERRORS,
       ["config system console\n set output standard\n end"], ["quit\n"]),

    _t("fortinet", "banner", "FortiGate - SSH - Banner Prompt",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+\s*#\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, FORTINET_CMDS, FORTINET_PAGINATION, FORTINET_ERRORS,
       ["config system console\n set output standard\n end"], ["quit\n"]),

    # ---- Palo Alto (4 templates) ----
    _t("paloalto", "panos-ssh", "Palo Alto - SSH",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login as:", "password_pattern": r"Password:"},
       None, PANOS_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, PANOS_ERRORS,
       ["set cli pager off"], ["quit"]),

    _t("paloalto", "panos-9x", "Palo Alto v9.x - SSH",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login as:", "password_pattern": r"Password:"},
       None, PANOS_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, PANOS_ERRORS,
       ["set cli pager off"], ["quit"]),

    _t("paloalto", "panos-v2", "Palo Alto - SSH v2",
       SSH_ONLY(timeout=5),
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login as:", "password_pattern": r"Password:"},
       PRIV_ENABLE(cmd="set cli scripting-mode on"), PANOS_CMDS, {"enabled": False}, PANOS_ERRORS,
       ["set cli scripting-mode on\nset cli pager off"], ["quit"]),

    _t("paloalto", "panos-vector", "Palo Alto - SSH - Config (Vector)",
       SSH_ONLY(timeout=10),
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login as:", "password_pattern": r"Password:"},
       PRIV_ENABLE(cmd="set cli pager off\n set cli config-output-format set\n"),
       PANOS_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, PANOS_ERRORS,
       ["configure"], ["quit"]),

    # ---- Juniper (1 template) ----
    _t("juniper", "junos-ssh", "Juniper JunOS - SSH",
       SSH_ONLY(timeout=60),
       {"patterns": [r"\S+@\S+>\s*$", r"\S+@\S+#\s*$"], "login_pattern": r"login:", "password_pattern": r"password:"},
       None, JUNIPER_CMDS, JUNIPER_PAGINATION, JUNIPER_ERRORS,
       ["set cli screen-length 0"], ["exit"]),

    # ---- MikroTik additional variants (3) ----
    _t("mikrotik", "routeros-banner", "MikroTik RouterOS - SSH - Banner",
       SSH_ONLY(timeout=10),
       {"patterns": [r"\[[^\]\r\n]+@[^\]\r\n]+\][^\r\n]*?[>#]\s*$"], "login_pattern": r"Login:", "password_pattern": r"Password:"},
       None, MIKROTIK_CMDS, {"enabled": False}, MIKROTIK_ERRORS,
       [], ["/quit"]),

    _t("mikrotik", "routeros-noninteractive", "MikroTik RouterOS - SSH - NonInteractive",
       {"default_port_ssh": 22, "default_port_telnet": 23, "timeout": 10, "protocols": ["ssh"], "is_non_interactive": True},
       {"patterns": [r"\[[^\]\r\n]+@[^\]\r\n]+\][^\r\n]*?[>#]\s*$"], "login_pattern": r"Login:", "password_pattern": r"Password:"},
       None, MIKROTIK_CMDS, {"enabled": False}, MIKROTIK_ERRORS,
       [], ["/quit"]),

    _t("mikrotik", "routeros-v2", "MikroTik RouterOS - SSH v2",
       SSH_ONLY(timeout=10),
       {"patterns": [r"\[[^\]\r\n]+@[^\]\r\n]+\][^\r\n]*?[>#]\s*$"], "login_pattern": r"Login:", "password_pattern": r"Password:"},
       None, MIKROTIK_CMDS, {"enabled": False}, MIKROTIK_ERRORS,
       [], ["/quit"]),

    # ---- Brocade (1 template) ----
    _t("brocade", "ssh", "Brocade - SSH",
       SSH(timeout=30),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"Username:", "password_pattern": r"password:"},
       None, BROCADE_CMDS, BROCADE_PAGINATION, BROCADE_ERRORS,
       ["skip-page-display"], ["quit"]),

    # ---- Check Point (1 template) ----
    _t("checkpoint", "gaia-ssh", "Check Point Gaia OS - SSH",
       SSH_ONLY(timeout=30), PROMPT_LOGIN(login="login:", passwd="Password:"),
       PRIV_ENABLE(cmd="enable"), CHECKPOINT_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, CHECKPOINT_ERRORS,
       ["set clienv rows 0"], ["exit"]),

    # ---- Ciena (2 templates) ----
    _t("ciena", "6500-tl1", "Ciena 6500 - TL1",
       SSH_ONLY(timeout=30),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, CIENA_TL1_CMDS, {"enabled": False}, CIENA_TL1_ERRORS,
       [], ["exit"]),

    _t("ciena", "6500-tl1-telnet", "Ciena 6500 - TL1 - Telnet",
       TELNET(timeout=30),
       {"patterns": [r"\S+#\s*$", r"\S+>\s*$"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       None, CIENA_TL1_CMDS, {"enabled": False}, CIENA_TL1_ERRORS,
       [], ["exit"]),

    # ---- Ruckus (2 templates) ----
    _t("ruckus", "ssh-enable", "Ruckus - SSH - Enable",
       SSH_ONLY(timeout=30), PROMPT_UP(), PRIV_ENABLE(),
       RUCKUS_CMDS, RUCKUS_PAGINATION, RUCKUS_ERRORS,
       [], ["exit"]),

    _t("ruckus", "ssh-noenable", "Ruckus - SSH - No Enable",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       RUCKUS_CMDS, RUCKUS_PAGINATION, RUCKUS_ERRORS,
       [], ["exit"]),

    # ---- SonicWall (2 templates) ----
    _t("sonicwall", "ssh", "SonicWall - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(), SONICWALL_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, SONICWALL_ERRORS,
       ["terminal pager disable"], ["exit"]),

    _t("sonicwall", "ssh-confirm", "SonicWall - SSH - Confirm Banner",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(), SONICWALL_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, SONICWALL_ERRORS,
       ["terminal pager disable"], ["exit"]),

    # ---- Ubiquiti (1 template) ----
    _t("ubiquiti", "unifi-ssh", "Ubiquiti UniFi - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["exit"]),

    # ---- VyOS (1 template) ----
    _t("vyos", "ssh", "VyOS - SSH",
       SSH_ONLY(timeout=30), PROMPT_LOGIN(login="login:", passwd="Password:"),
       PRIV_ENABLE(cmd="configure"), GENERIC_CMDS,
       {"enabled": False}, GENERIC_ERRORS,
       ["set terminal length 0"], ["exit"]),

    # ---- Extreme (1 template) ----
    _t("extreme", "summit-ssh", "Extreme Summit - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["disable clipaging"], ["exit"]),

    # ---- Allied Telesis (1 template) ----
    _t("allied_telesis", "ssh", "Allied Telesis - SSH - Enable",
       SSH_ONLY(timeout=30), PROMPT_UP(), PRIV_ENABLE(),
       GENERIC_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["exit"]),

    # ---- Adtran (1 template) ----
    _t("adtran", "telnet", "Adtran 900 - Telnet",
       TELNET(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["exit"]),

    # ---- ADVA (1 template) ----
    _t("adva", "ssh", "ADVA - SSH - No Enable",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       GENERIC_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- AudioCodes (1 template) ----
    _t("audiocodes", "ssh", "AudioCodes - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- Avaya (2 templates) ----
    _t("avaya", "4526-telnet", "Avaya 4526GTX - Telnet - No Enable",
       TELNET(timeout=30), PROMPT_UP(), None,
       AVAYA_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, AVAYA_ERRORS,
       ["terminal length 0"], ["quit"]),

    _t("avaya", "ers-ssh", "Avaya ERS - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), AVAYA_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, AVAYA_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- Calix (1 template) ----
    _t("calix", "axos-ssh", "Calix AXOS - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       GENERIC_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["exit"]),

    # ---- DiGi (1 template) ----
    _t("digi", "ix20-ssh", "DiGi IX20 - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- Edge-Core (1 template) ----
    _t("edge_core", "ssh", "Edge-Core - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       GENERIC_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- Mellanox (1 template) ----
    _t("mellanox", "ssh", "Mellanox - SSH - Enable",
       SSH_ONLY(timeout=30), PROMPT_UP(), PRIV_ENABLE(),
       GENERIC_CMDS, {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["quit"]),

    # ---- NVIDIA / InfiniBand (1 template) ----
    _t("nvidia", "ib-ssh", "NVIDIA InfiniBand - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       GENERIC_CMDS, {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- pfSense (1 template) ----
    _t("pfsense", "ssh", "pfSense - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="su"), GENERIC_CMDS,
       {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- RAD (1 template) ----
    _t("rad", "ssh", "RAD - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(), None,
       GENERIC_CMDS, {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- Siemens / RuggedCom (1 template) ----
    _t("siemens", "ruggedcom-ssh", "Siemens RuggedCom ROS - SSH",
       SSH_ONLY(timeout=30), PROMPT_UP(),
       PRIV_ENABLE(cmd="enable"), GENERIC_CMDS,
       {"enabled": True, "pattern": "--More--", "key": "space"}, GENERIC_ERRORS,
       ["terminal length 0"], ["exit"]),

    # ---- Linux (1 template from rConfig - SSH only) ----
    _t("linux", "centos-ssh", "Linux CentOS - SSH",
       SSH_ONLY(timeout=30),
       {"patterns": [r"\$\s*$", r"#\s*$"], "login_pattern": r"login:", "password_pattern": r"Password:"},
       PRIV_ENABLE(cmd="sudo -i", prompt=r"#\s*$"), GENERIC_CMDS,
       {"enabled": False}, GENERIC_ERRORS,
       [], ["exit"]),

    # ---- Huawei (1 template from rConfig) ----
    _t("huawei", "vrp-ssh", "Huawei VRP - SSH",
       SSH_ONLY(timeout=30),
       {"patterns": [r"\<[\w\-]+\>", r"\[[\w\-]+\]"], "login_pattern": r"Username:", "password_pattern": r"Password:"},
       PRIV_ENABLE(cmd="system-view", prompt=r"\[\S+\]"), GENERIC_CMDS,
       {"enabled": True, "pattern": "---- More ----", "key": "space"}, {"patterns": ["Error:", "Unrecognized", "Incomplete"]},
       ["screen-length 0 temporary"], ["return", "quit"]),
]

# -------------------------------------------------------------------------
# Brands to insert (all rConfig vendors not already in device_brands)
# -------------------------------------------------------------------------

RCONFIG_BRANDS = [
    ("hp", "HP"),
    ("dell", "Dell"),
    ("aruba", "Aruba"),
    ("paloalto", "Palo Alto Networks"),
    ("brocade", "Brocade"),
    ("checkpoint", "Check Point"),
    ("ciena", "Ciena"),
    ("sonicwall", "SonicWall"),
    ("ruckus", "Ruckus"),
    ("ubiquiti", "Ubiquiti"),
    ("vyos", "VyOS"),
    ("extreme", "Extreme Networks"),
    ("allied_telesis", "Allied Telesis"),
    ("adtran", "Adtran"),
    ("adva", "ADVA Optical"),
    ("audiocodes", "AudioCodes"),
    ("avaya", "Avaya"),
    ("calix", "Calix"),
    ("digi", "Digi"),
    ("edge_core", "Edge-Core"),
    ("mellanox", "Mellanox"),
    ("nvidia", "NVIDIA Networking"),
    ("pfsense", "pfSense"),
    ("rad", "RAD"),
    ("siemens", "Siemens"),
]

# -------------------------------------------------------------------------
# Migrate
# -------------------------------------------------------------------------

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return

    # 1. Add is_system column to device_brands if not present
    migrator.sql("ALTER TABLE device_brands ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE")

    # 1b. PAM device_connections columns (needed by non-MikroTik device
    # management in BOTH tiers — moved out of the PRO migration).
    migrator.sql("ALTER TABLE device_connections ADD COLUMN IF NOT EXISTS agent_modes JSONB")
    migrator.sql("ALTER TABLE device_connections ADD COLUMN IF NOT EXISTS privileged_credential_id INT REFERENCES credentials(id) ON DELETE SET NULL")

    # 2. Mark existing brands as system
    migrator.sql("UPDATE device_brands SET is_system = TRUE WHERE is_system = FALSE")

    # 3. Insert base + rConfig brands
    now_sql = "NOW()"
    for brand, display_name in BASE_BRANDS + RCONFIG_BRANDS:
        migrator.sql(
            f"INSERT INTO device_brands (brand, display_name, is_active, is_system, created) "
            f"VALUES ('{brand}', '{display_name}', TRUE, TRUE, {now_sql}) "
            f"ON CONFLICT (brand) DO UPDATE SET is_system = TRUE"
        )

    # 4. Insert base + rConfig templates
    for t in BASE_TEMPLATES + RCONFIG_TEMPLATES:
        migrator.sql(f"""
            INSERT INTO public.device_templates
                (brand, os_type, display_name, connection, prompt, privilege_escalation,
                 commands, pagination, error_patterns, post_login_commands, pre_logout_commands,
                 is_system, is_active)
            VALUES (
                '{t['brand']}', '{t['os_type']}', '{t['display_name']}',
                {_sql_str(t['connection'])}, {_sql_str(t['prompt'])}, {_sql_str(t['privilege_escalation'])},
                {_sql_str(t['commands'])}, {_sql_str(t['pagination'])}, {_sql_str(t['error_patterns'])},
                {_sql_str(t['post_login_commands'])}, {_sql_str(t['pre_logout_commands'])},
                TRUE, TRUE
            ) ON CONFLICT (brand, os_type) DO NOTHING
        """)

    log.info(f"Migration 052: seeded {len(BASE_BRANDS) + len(RCONFIG_BRANDS)} brands and {len(BASE_TEMPLATES) + len(RCONFIG_TEMPLATES)} templates")

def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    # Rollback: remove rConfig templates and brands
    for t in BASE_TEMPLATES + RCONFIG_TEMPLATES:
        brand = t['brand']
        os_type = t['os_type']
        migrator.sql(f"DELETE FROM device_templates WHERE brand='{brand}' AND os_type='{os_type}' AND is_system=TRUE")
    for brand, _ in BASE_BRANDS + RCONFIG_BRANDS:
        migrator.sql(f"DELETE FROM device_brands WHERE brand='{brand}' AND is_system=TRUE")
    # NOTE: does not drop the is_system column (other code may depend on it now)
