# 060_diff_exclusions_all_brands.py
#

import json
import logging

log = logging.getLogger("migration_060")


def _sql_jsonb(v):
    if v is None:
        return "NULL"
    s = json.dumps(v)
    s = s.replace("'", "''")
    s = s.replace("%", "%%")
    return "'{}'::jsonb".format(s)


def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return

    # 1. MikroTik RouterOS — update ALL variants (ID 1, 39, 40, 41)
    mikrotik_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^#\s+.*?\s+by\s+RouterOS.*$", "flags": ""},
            {"pattern": r"^#\s*(software|system)\s*id\s*=.*$", "flags": "i"},
            {"pattern": r"^#\s*model\s*=.*$", "flags": "i"},
            {"pattern": r"^#\s*serial\s*number\s*=.*$", "flags": "i"},
            {"pattern": r"^#\s*$", "flags": ""},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'mikrotik' AND is_system = TRUE
    """.format(excl=_sql_jsonb(mikrotik_excl)))

    # Increase timeout for MikroTik variants from 10s to 60s
    migrator.sql("""
        UPDATE device_templates
           SET connection = jsonb_set(connection, '{timeout}', '60'::jsonb)
         WHERE brand = 'mikrotik' AND is_system = TRUE AND (connection->>'timeout')::int < 60
    """)

    # Ensure show_config has {export_flags} across all MikroTik templates
    migrator.sql("""
        UPDATE device_templates
           SET commands = jsonb_set(commands, '{show_config}', '"/export terse{export_flags}"'::jsonb)
         WHERE brand = 'mikrotik' AND is_system = TRUE
    """)

    # 2. Cisco — enhance exclusions with additional volatile lines
    cisco_excl = {
        "global": [
            {"pattern": r"^!\s*Last configuration change at.*$", "flags": ""},
            {"pattern": r"^!\s*NVRAM config last updated at.*$", "flags": ""},
            {"pattern": r"^!\s*No configuration change since.*$", "flags": "i"},
            {"pattern": r"^!\s*Configuration last modified by.*$", "flags": "i"},
            {"pattern": r"^.*uptime is.*$", "flags": "i"},
        ],
        "show_config": [
            {"pattern": r"^!\s*Time:.*$", "flags": ""},
            {"pattern": r"^Current configuration : \d+ bytes$", "flags": ""},
            {"pattern": r"^Building configuration\.\.\.$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'cisco' AND is_system = TRUE
    """.format(excl=_sql_jsonb(cisco_excl)))

    # 3. Fortinet (FortiGate / FortiOS)
    fortinet_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^#\s*(config-version|date|time|build|timestamp)\s*[:=].*$", "flags": "i"},
            {"pattern": r"^#\s*building-configuration.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'fortinet' AND is_system = TRUE
    """.format(excl=_sql_jsonb(fortinet_excl)))

    # Increase Fortinet timeout from 5s to 60s
    migrator.sql("""
        UPDATE device_templates
           SET connection = jsonb_set(connection, '{timeout}', '60'::jsonb)
         WHERE brand = 'fortinet' AND is_system = TRUE AND (connection->>'timeout')::int < 60
    """)

    # 4. Juniper JunOS
    juniper_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^##?\s*Last (changed|commit).*$", "flags": "i"},
            {"pattern": r"^##?\s*commit-time:.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'juniper' AND is_system = TRUE
    """.format(excl=_sql_jsonb(juniper_excl)))

    # 5. Huawei VRP
    huawei_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^#\s*Last configuration (was )?updated at.*$", "flags": "i"},
            {"pattern": r"^#\s*Current configuration\s*:\s*\d+.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'huawei' AND is_system = TRUE
    """.format(excl=_sql_jsonb(huawei_excl)))

    # 6. HP / Aruba ProCurve / FlexFabric / Comware / H3C
    hp_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^;\s*Time:\s*.*$", "flags": "i"},
            {"pattern": r"^;\s*Created on release.*$", "flags": "i"},
            {"pattern": r"^;\s*Configuration Editor.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'hp' AND is_system = TRUE
    """.format(excl=_sql_jsonb(hp_excl)))

    # Increase HP timeout from 5s to 60s
    migrator.sql("""
        UPDATE device_templates
           SET connection = jsonb_set(connection, '{timeout}', '60'::jsonb)
         WHERE brand = 'hp' AND is_system = TRUE AND (connection->>'timeout')::int < 60
    """)

    # 7. Dell (PowerConnect / Force10)
    dell_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^!\s*Time:\s*.*$", "flags": "i"},
            {"pattern": r"^!\s*Last configuration change at.*$", "flags": "i"},
            {"pattern": r"^!\s*System Description.*$", "flags": "i"},
            {"pattern": r"^!\s*Current Configuration.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'dell' AND is_system = TRUE
    """.format(excl=_sql_jsonb(dell_excl)))

    # Increase Dell timeout from 5s to 60s
    migrator.sql("""
        UPDATE device_templates
           SET connection = jsonb_set(connection, '{timeout}', '60'::jsonb)
         WHERE brand = 'dell' AND is_system = TRUE AND (connection->>'timeout')::int < 60
    """)

    # 8. Palo Alto — increase timeout from 5s to 60s
    migrator.sql("""
        UPDATE device_templates
           SET connection = jsonb_set(connection, '{timeout}', '60'::jsonb)
         WHERE brand = 'paloalto' AND is_system = TRUE AND (connection->>'timeout')::int < 60
    """)

    # 9. VyOS & Ubiquiti
    vyos_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^#\s*(Last (modified|changed|saved)|Configuration generated).*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand IN ('vyos', 'ubiquiti') AND is_system = TRUE
    """.format(excl=_sql_jsonb(vyos_excl)))

    # 10. SonicWall
    sonicwall_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^Time:\s*.*$", "flags": "i"},
        ],
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl}
         WHERE brand = 'sonicwall' AND is_system = TRUE
    """.format(excl=_sql_jsonb(sonicwall_excl)))

    log.info("Migration 060 applied: diff exclusions and timeouts updated across all device brands.")


def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    # Reset non-cisco exclusions to {}
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = '{}'::jsonb
         WHERE brand NOT IN ('cisco') AND is_system = TRUE
    """)
