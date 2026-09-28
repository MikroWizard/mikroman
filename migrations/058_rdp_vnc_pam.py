# 058_rdp_vnc_pam_pro.py
# Adds 4-tier cascading hierarchy and Web-centric PAM Session DLP for RDP/VNC sessions.
# 1. Adds parent_id (self-referential FK) and protocol_config (JSONB) to devices.
# 2. Adds session_dlp (JSONB) to terminal_policies_pro.
# 3. Seeds pre-defined connection templates for RDP and VNC.

import json
import logging

log = logging.getLogger("migration_058")

DEFAULT_SESSION_DLP = {
    "clipboard": "bidirectional",
    "file_transfer": "enabled",
    "watermark": {
        "enabled": False,
        "text": "{user} ({ip}) - {date}",
        "opacity": 0.15
    },
    "recording": {
        "video_enabled": True,
        "keystrokes_enabled": True
    },
    "printing": False,
    "audio_input": False
}

SYSTEM_TEMPLATES_058 = [
    {
        "brand": "windows",
        "os_type": "rdp-standard",
        "display_name": "Standard Office RDP (Full Desktop)",
        "connection": {
            "protocol": "rdp",
            "protocols": ["rdp"],
            "port": 3389,
            "security": "any",
            "ignore_cert": True,
            "color_depth": 32,
            "dpi": 96,
            "enable_wallpaper": True,
            "enable_theming": True,
            "enable_font_smoothing": True,
            "enable_full_window_drag": True,
            "enable_desktop_composition": True,
            "enable_menu_animations": False,
            "disable_audio": False,
            "enable_audio_input": False,
            "enable_printing": False,
            "server_layout": "en-us-qwerty",
            "timezone": "UTC"
        }
    },
    {
        "brand": "windows",
        "os_type": "rdp-cad",
        "display_name": "High-Performance / CAD RDP",
        "connection": {
            "protocol": "rdp",
            "protocols": ["rdp"],
            "port": 3389,
            "security": "any",
            "ignore_cert": True,
            "color_depth": 32,
            "dpi": 96,
            "force_lossless": True,
            "enable_wallpaper": True,
            "enable_theming": True,
            "enable_font_smoothing": True,
            "enable_full_window_drag": True,
            "enable_desktop_composition": True,
            "enable_menu_animations": True,
            "disable_audio": False,
            "enable_audio_input": False,
            "server_layout": "en-us-qwerty",
            "timezone": "UTC"
        }
    },
    {
        "brand": "windows",
        "os_type": "rdp-low-bandwidth",
        "display_name": "Low-Bandwidth / WAN RDP",
        "connection": {
            "protocol": "rdp",
            "protocols": ["rdp"],
            "port": 3389,
            "security": "any",
            "ignore_cert": True,
            "color_depth": 16,
            "dpi": 96,
            "enable_wallpaper": False,
            "enable_theming": False,
            "enable_font_smoothing": False,
            "enable_full_window_drag": False,
            "enable_desktop_composition": False,
            "enable_menu_animations": False,
            "disable_audio": True,
            "server_layout": "en-us-qwerty"
        }
    },
    {
        "brand": "windows",
        "os_type": "rdp-remoteapp",
        "display_name": "RemoteApp Baseline (Seamless)",
        "connection": {
            "protocol": "rdp",
            "protocols": ["rdp"],
            "port": 3389,
            "security": "any",
            "ignore_cert": True,
            "color_depth": 32,
            "dpi": 96,
            "enable_font_smoothing": True,
            "enable_theming": True,
            "disable_audio": False,
            "server_layout": "en-us-qwerty"
        }
    },
    {
        "brand": "generic",
        "os_type": "vnc-console",
        "display_name": "VNC Console Minimal",
        "connection": {
            "protocol": "vnc",
            "protocols": ["vnc"],
            "port": 5900,
            "read_only": False,
            "color_depth": 24
        }
    }
]


def _sql_str(val):
    if val is None:
        return "NULL"
    if isinstance(val, (dict, list)):
        val = json.dumps(val)
    escaped = str(val).replace("'", "''")
    return f"'{escaped}'"


def migrate(migrator, database, fake=False, **kwargs):
    # 1. devices table additions
    migrator.sql("""
        ALTER TABLE devices
        ADD COLUMN IF NOT EXISTS parent_id INT REFERENCES devices(id) ON DELETE CASCADE,
        ADD COLUMN IF NOT EXISTS protocol_config JSONB NOT NULL DEFAULT '{}'::jsonb
    """)

    migrator.sql("""
        CREATE INDEX IF NOT EXISTS idx_devices_parent_id ON devices(parent_id) WHERE parent_id IS NOT NULL
    """)

    # 2. terminal_policies_pro table additions (safe if table exists in Pro, ignored in Free)
    dlp_json_str = json.dumps(DEFAULT_SESSION_DLP).replace("'", "''")
    migrator.sql(f"""
        DO 30808
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'terminal_policies_pro') THEN
                ALTER TABLE terminal_policies_pro
                ADD COLUMN IF NOT EXISTS session_dlp JSONB NOT NULL DEFAULT '{dlp_json_str}'::jsonb;

                UPDATE terminal_policies_pro
                SET session_dlp = '{dlp_json_str}'::jsonb
                WHERE session_dlp IS NULL;
            END IF;
        END 30808;
    """)

    # 3. Ensure windows and generic brands exist
    migrator.sql("""
        INSERT INTO device_brands (brand, display_name, is_active, is_system, created)
        VALUES ('windows', 'Windows', TRUE, TRUE, NOW())
        ON CONFLICT (brand) DO UPDATE SET is_active = TRUE
    """)

    migrator.sql("""
        INSERT INTO device_brands (brand, display_name, is_active, is_system, created)
        VALUES ('generic', 'Generic', TRUE, TRUE, NOW())
        ON CONFLICT (brand) DO UPDATE SET is_active = TRUE
    """)

    # 4. Seed system connection templates
    for t in SYSTEM_TEMPLATES_058:
        migrator.sql(f"""
            INSERT INTO public.device_templates
                (brand, os_type, display_name, connection, is_system, is_active, created)
            VALUES (
                '{t['brand']}', '{t['os_type']}', '{t['display_name']}',
                {_sql_str(t['connection'])}, TRUE, TRUE, NOW()
            )
            ON CONFLICT (brand, os_type) DO UPDATE
            SET connection = EXCLUDED.connection,
                display_name = EXCLUDED.display_name,
                is_active = TRUE
        """)

    log.info("Migration 058 applied: devices parent_id/protocol_config, session_dlp, and RDP/VNC templates seeded.")


def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return

    for t in SYSTEM_TEMPLATES_058:
        migrator.sql(f"DELETE FROM device_templates WHERE brand='{t['brand']}' AND os_type='{t['os_type']}' AND is_system=TRUE")

    migrator.sql("""
        DO 30808
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'terminal_policies_pro') THEN
                ALTER TABLE terminal_policies_pro DROP COLUMN IF EXISTS session_dlp;
            END IF;
        END 30808;
    """)
    migrator.sql("DROP INDEX IF EXISTS idx_devices_parent_id")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS protocol_config")
    migrator.sql("ALTER TABLE devices DROP COLUMN IF EXISTS parent_id")

