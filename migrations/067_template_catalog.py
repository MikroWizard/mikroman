# 067_template_catalog.py
# Signed online updates of the system device templates (libs/template_catalog.py):
#   template_catalog        received catalogs (verified, newest wins)
#   template_catalog_state  catalog revision + baseline content per installed system template
#   template_history        template content before every catalog update / revert / admin edit
# Settings: template_update_mode (notify | auto | off), template_channel (stable | beta).
# Template contents are not changed here: updates are applied from the Template Manager
# (or automatically in 'auto' mode, only for templates nobody edited).

import logging

log = logging.getLogger("migration_067")


def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.template_catalog (
            id               SERIAL PRIMARY KEY,
            catalog_version  INTEGER NOT NULL,
            channel          TEXT NOT NULL DEFAULT 'stable',
            origin           TEXT NOT NULL,
            catalog          JSONB NOT NULL,
            signature        TEXT NOT NULL,
            received_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_template_catalog_version ON public.template_catalog(catalog_version)")
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.template_catalog_state (
            template_id       INTEGER PRIMARY KEY REFERENCES public.device_templates(id) ON DELETE CASCADE,
            template_key      TEXT NOT NULL,
            revision          INTEGER NOT NULL DEFAULT 0,
            baseline          JSONB NULL,
            skipped_revision  INTEGER NOT NULL DEFAULT 0,
            updated_at        TIMESTAMP WITH TIME ZONE NULL
        )
    """)
    migrator.sql("""
        CREATE TABLE IF NOT EXISTS public.template_history (
            id            SERIAL PRIMARY KEY,
            template_id   INTEGER NOT NULL REFERENCES public.device_templates(id) ON DELETE CASCADE,
            template_key  TEXT NULL,
            revision      INTEGER NULL,
            content       JSONB NOT NULL,
            reason        TEXT NOT NULL,
            changed_by    TEXT NULL,
            changed_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_template_history_template ON public.template_history(template_id, id)")
    for key, value in (("template_update_mode", "notify"), ("template_channel", "stable")):
        migrator.sql(
            "INSERT INTO public.sysconfig (key, value, created, modified) VALUES ('{}', '{}', NOW(), NOW()) "
            "ON CONFLICT (key) DO NOTHING".format(key, value))
    log.info("Migration 067: template catalog tables ready")


def rollback(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("DROP TABLE IF EXISTS public.template_history")
    migrator.sql("DROP TABLE IF EXISTS public.template_catalog_state")
    migrator.sql("DROP TABLE IF EXISTS public.template_catalog")
    migrator.sql("DELETE FROM public.sysconfig WHERE key IN ('template_update_mode', 'template_channel')")
