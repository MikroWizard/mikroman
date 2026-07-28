# 053_multi_brand_automation.py
# Multi-brand automation layer: config versioning, execution logging,
# diff exclusions, pre/post connection hooks, snippet extensions.
# FREE tier — all tables are public/core.
#
# STOP: After creating this file, ask the user to run the migration
# manually before proceeding to any code that depends on these tables.

import json


def _sql_jsonb(v):
    if v is None:
        return "NULL"
    s = json.dumps(v)
    s = s.replace("'", "''")
    s = s.replace("%", "%%")
    return "'{}'::jsonb".format(s)


def migrate(migrator, database, fake=False, **kwargs):
    # ----------------------------------------------------------------
    # 1. device_templates — new columns
    # ----------------------------------------------------------------
    migrator.sql("ALTER TABLE device_templates ADD COLUMN IF NOT EXISTS diff_exclusions JSONB DEFAULT '{}'::jsonb")
    migrator.sql("ALTER TABLE device_templates ADD COLUMN IF NOT EXISTS pre_connect JSONB DEFAULT '[]'::jsonb")
    migrator.sql("ALTER TABLE device_templates ADD COLUMN IF NOT EXISTS post_disconnect JSONB DEFAULT '[]'::jsonb")
    migrator.sql("ALTER TABLE device_templates ADD COLUMN IF NOT EXISTS config_mode JSONB DEFAULT NULL")

    # ----------------------------------------------------------------
    # 2. snippets — brand + defaults (no mass-backfill of is_default)
    # ----------------------------------------------------------------
    migrator.sql("ALTER TABLE snippets ADD COLUMN IF NOT EXISTS brand VARCHAR(50) NOT NULL DEFAULT 'mikrotik'")
    migrator.sql("ALTER TABLE snippets ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE")
    migrator.sql("ALTER TABLE snippets ADD COLUMN IF NOT EXISTS is_config_mode BOOLEAN NOT NULL DEFAULT FALSE")
    migrator.sql("UPDATE snippets SET brand = 'mikrotik' WHERE brand IS NULL OR brand = ''")

    # ----------------------------------------------------------------
    # 3. config_versions
    # ----------------------------------------------------------------
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.config_versions (
            id                   SERIAL       PRIMARY KEY,
            device_id            INT          NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            template_id          INT          REFERENCES device_templates(id) ON DELETE SET NULL,
            command_key          VARCHAR(100) NOT NULL DEFAULT 'show_config',
            version_num          INT          NOT NULL,
            normalized_hash      VARCHAR(64)  NOT NULL,
            storage_path         TEXT         NOT NULL,
            size_bytes           INT          NOT NULL DEFAULT 0,
            previous_version_id  INT          REFERENCES config_versions(id) ON DELETE SET NULL,
            first_seen_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            last_seen_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );
    """)
    # Expression UNIQUE index (Postgres won't allow COALESCE in table-level
    # UNIQUE constraint; unique index handles NULL template_id correctly).
    migrator.sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cv_unique
            ON public.config_versions (device_id, COALESCE(template_id, 0), command_key, version_num);
    """)
    migrator.sql("""
        CREATE INDEX IF NOT EXISTS idx_cv_device_key
            ON public.config_versions (device_id, command_key, version_num DESC);
    """)
    migrator.sql("""
        CREATE INDEX IF NOT EXISTS idx_cv_hash
            ON public.config_versions (normalized_hash);
    """)

    # ----------------------------------------------------------------
    # 4. command_execution_log (high-volume — see plan §13.3)
    # ----------------------------------------------------------------
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.command_execution_log (
            id                BIGSERIAL    PRIMARY KEY,
            user_task_id      INT          REFERENCES user_tasks(id) ON DELETE SET NULL,
            execution_run_id  UUID         NOT NULL,
            device_id         INT          NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            template_id       INT          REFERENCES device_templates(id) ON DELETE SET NULL,
            command_key       VARCHAR(100),
            command_string    TEXT         NOT NULL,
            status            VARCHAR(20)  NOT NULL DEFAULT 'ok',
            error_message     TEXT,
            duration_ms       INT          DEFAULT 0,
            is_versioned      BOOLEAN      NOT NULL DEFAULT FALSE,
            version_id        INT          REFERENCES config_versions(id) ON DELETE SET NULL,
            normalized_hash   VARCHAR(64),
            storage_path      TEXT,
            raw_hash          VARCHAR(64),
            raw_storage_path  TEXT,
            raw_size_bytes    INT          DEFAULT 0,
            executed_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_device_time ON public.command_execution_log (device_id, executed_at DESC)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_run         ON public.command_execution_log (execution_run_id)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_user_task   ON public.command_execution_log (user_task_id)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_status      ON public.command_execution_log (status)")

    # ----------------------------------------------------------------
    # 5. user_tasks — lease columns for distributed cron claim
    # ----------------------------------------------------------------
    migrator.sql("ALTER TABLE user_tasks ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ")
    migrator.sql("ALTER TABLE user_tasks ADD COLUMN IF NOT EXISTS locked_by VARCHAR(100)")

    # ----------------------------------------------------------------
    # 6. MikroTik RouterOS template — canonical exclusions + hooks +
    #    version-aware export (export_flags placeholder substituted by
    #    pre_connect hook at runtime)
    # ----------------------------------------------------------------
    diff_excl = {
        "global": [],
        "show_config": [
            {"pattern": r"^#\s+\S+\s+\S+\s+by\s+.+$", "flags": ""},
            {"pattern": r"^#\s+Software ID\s*=.*$", "flags": ""},
        ],
    }
    pre_conn = [{
        "type": "routeros_api",
        "path": "/ip/service",
        "filter": {"name": "ssh"},
        "action": "enable",
        "capture_field": "port",
        "save_state_key": "ssh_was_disabled",
        "capture_export_flags": True,
    }]
    post_conn = [{
        "type": "routeros_api",
        "path": "/ip/service",
        "filter": {"name": "ssh"},
        "action": "restore",
        "state_key": "ssh_was_disabled",
    }]
    new_cmds = {
        "show_config": "/export terse{export_flags}",
        "show_interfaces": "/interface print",
        "show_routing": "/ip route print",
        "show_arp": "/ip arp print",
        "show_version": ":put [/system resource get version]",
        "show_log": "/log print",
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions   = {diff_exclusions},
               pre_connect       = {pre_connect},
               post_disconnect   = {post_disconnect},
               commands          = {commands}
         WHERE brand = 'mikrotik' AND os_type = 'routeros' AND is_system = TRUE
    """.format(
        diff_exclusions=_sql_jsonb(diff_excl),
        pre_connect=_sql_jsonb(pre_conn),
        post_disconnect=_sql_jsonb(post_conn),
        commands=_sql_jsonb(new_cmds),
    ))

    # ----------------------------------------------------------------
    # 7. Cisco-family templates — seed canonical exclusions
    # ----------------------------------------------------------------
    cisco_excl = {
        "global": [
            {"pattern": r"^!\s*Last configuration change at.*$", "flags": ""},
            {"pattern": r"^!\s*NVRAM config last updated at.*$", "flags": ""},
            {"pattern": r"^.*uptime is.*$", "flags": "i"},
        ],
        "show_config": [
            {"pattern": r"^!\s*Time:.*$", "flags": ""},
            {"pattern": r"^Current configuration : \\d+ bytes$", "flags": ""},
        ],
    }
    cisco_config_mode = {
        "enter": "configure terminal",
        "exit": "end",
        "save": None,
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions = {excl},
               config_mode     = {cmode}
         WHERE brand = 'cisco'
           AND diff_exclusions = '{{}}'::jsonb
    """.format(
        excl=_sql_jsonb(cisco_excl),
        cmode=_sql_jsonb(cisco_config_mode),
    ))


def rollback(migrator, database, fake=False, **kwargs):
    # Reverse order

    # 7 — reset Cisco exclusions
    migrator.sql("UPDATE device_templates SET diff_exclusions = '{}'::jsonb, config_mode = NULL WHERE brand = 'cisco' AND diff_exclusions != '{}'::jsonb")

    # 6 — reset MikroTik
    mikrotik_orig_cmds = {
        "show_config": "/export terse",
        "show_interfaces": "/interface print",
        "show_routing": "/ip route print",
        "show_arp": "/ip arp print",
        "show_version": ":put [/system resource get version]",
        "show_log": "/log print",
    }
    migrator.sql("""
        UPDATE device_templates
           SET diff_exclusions   = '{{}}'::jsonb,
               pre_connect       = '[]'::jsonb,
               post_disconnect   = '[]'::jsonb,
               commands          = {commands}
         WHERE brand = 'mikrotik' AND os_type = 'routeros' AND is_system = TRUE
    """.format(commands=_sql_jsonb(mikrotik_orig_cmds)))

    # 5
    migrator.sql("ALTER TABLE user_tasks DROP COLUMN IF EXISTS locked_by")
    migrator.sql("ALTER TABLE user_tasks DROP COLUMN IF EXISTS locked_at")

    # 4
    migrator.sql("DROP TABLE IF EXISTS public.command_execution_log CASCADE")

    # 3
    migrator.sql("DROP INDEX IF EXISTS idx_cv_unique")
    migrator.sql("DROP INDEX IF EXISTS idx_cv_device_key")
    migrator.sql("DROP INDEX IF EXISTS idx_cv_hash")
    migrator.sql("DROP TABLE IF EXISTS public.config_versions CASCADE")

    # 2
    migrator.sql("ALTER TABLE snippets DROP COLUMN IF EXISTS is_config_mode")
    migrator.sql("ALTER TABLE snippets DROP COLUMN IF EXISTS is_default")
    migrator.sql("ALTER TABLE snippets DROP COLUMN IF EXISTS brand")

    # 1
    migrator.sql("ALTER TABLE device_templates DROP COLUMN IF EXISTS config_mode")
    migrator.sql("ALTER TABLE device_templates DROP COLUMN IF EXISTS post_disconnect")
    migrator.sql("ALTER TABLE device_templates DROP COLUMN IF EXISTS pre_connect")
    migrator.sql("ALTER TABLE device_templates DROP COLUMN IF EXISTS diff_exclusions")
