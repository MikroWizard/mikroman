# 044_connection_core.py
# Creates the core connectivity tables cleanly using raw SQL (Free Tier).
# Only MikroTik is seeded by default. Pro features will seed other brands.

import json

def _sql_str(v):
    if v is None:
        return "NULL"
    s = json.dumps(v)
    s = s.replace("'", "''")
    s = s.replace("%", "%%")
    return "'{}'::jsonb".format(s)

SYSTEM_TEMPLATES = [
    {
        "brand": "mikrotik",
        "os_type": "routeros",
        "display_name": "MikroTik RouterOS",
        "connection": {
            "default_port_ssh": 22,
            "default_port_telnet": 23,
            "timeout": 30,
            "protocols": ["ssh", "telnet", "webfig"],
        },
        "prompt": {
            "patterns": [r"\] ?>", r"\] ?#"],
            "login_pattern": r"Login:",
            "password_pattern": r"Password:",
        },
        "privilege_escalation": None,
        "commands": {
            "show_config": "/export terse",
            "show_interfaces": "/interface print",
            "show_routing": "/ip route print",
            "show_arp": "/ip arp print",
            "show_version": ":put [/system resource get version]",
            "show_log": "/log print",
        },
        "pagination": {"enabled": False},
        "error_patterns": {"patterns": ["bad command", "no such item", "syntax error"]},
        "post_login_commands": [],
        "pre_logout_commands": ["/quit"],
    }
]

def migrate(migrator, database, fake=False, **kwargs):
    # device_brands
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.device_brands (
            brand        VARCHAR(50)  PRIMARY KEY,
            display_name VARCHAR(100) NOT NULL,
            is_active    BOOLEAN      NOT NULL DEFAULT true,
            created      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
    """)
    migrator.sql("INSERT INTO public.device_brands (brand, display_name) VALUES ('mikrotik', 'MikroTik') ON CONFLICT (brand) DO NOTHING")

    # device_templates
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.device_templates (
            id                   SERIAL      PRIMARY KEY,
            brand                VARCHAR(50) NOT NULL REFERENCES device_brands(brand),
            os_type              VARCHAR(50) NOT NULL,
            display_name         VARCHAR(100) NOT NULL,
            connection           JSONB,
            prompt               JSONB,
            privilege_escalation JSONB,
            commands             JSONB,
            pagination           JSONB,
            error_patterns       JSONB,
            post_login_commands  JSONB,
            pre_logout_commands  JSONB,
            is_system            BOOLEAN NOT NULL DEFAULT FALSE,
            is_active            BOOLEAN NOT NULL DEFAULT TRUE,
            created              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_brand_os UNIQUE (brand, os_type)
        )
    """)
    for t in SYSTEM_TEMPLATES:
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

    # credentials
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.credentials (
            id                   SERIAL       PRIMARY KEY,
            name                 VARCHAR(200) NOT NULL,
            credential_type      VARCHAR(20)  NOT NULL DEFAULT 'ssh',
            username             TEXT,
            encrypted_password   TEXT,
            dek_encrypted        TEXT         NOT NULL,
            auth_method          VARCHAR(20)  NOT NULL DEFAULT 'password',
            encrypted_private_key TEXT,
            passphrase_encrypted TEXT,
            scope                VARCHAR(20)  NOT NULL DEFAULT 'device',
            device_id            INT          REFERENCES devices(id) ON DELETE CASCADE,
            owner_id             UUID         REFERENCES users(id) ON DELETE SET NULL,
            notes                TEXT,
            created              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            modified             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_credentials_device_id ON public.credentials(device_id) WHERE device_id IS NOT NULL")

    # device_connections
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.device_connections (
            id                       SERIAL      PRIMARY KEY,
            device_id                INT         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            protocol                 VARCHAR(20) NOT NULL,
            port                     INT,
            credential_id            INT         REFERENCES credentials(id) ON DELETE SET NULL,
            auth_mode                VARCHAR(20) NOT NULL DEFAULT 'credential',
            is_default               BOOLEAN     NOT NULL DEFAULT FALSE,
            connection_type          VARCHAR(20) NOT NULL DEFAULT 'device',
            notes                    TEXT,
            created                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            modified                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_dev_conn UNIQUE (device_id, protocol)
        )
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_device_connections_credential_id ON public.device_connections(credential_id) WHERE credential_id IS NOT NULL")

def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("DROP TABLE IF EXISTS public.device_connections CASCADE")
    migrator.sql("DROP TABLE IF EXISTS public.credentials CASCADE")
    migrator.sql("DROP TABLE IF EXISTS public.device_templates CASCADE")
    migrator.sql("DROP TABLE IF EXISTS public.device_brands CASCADE")
