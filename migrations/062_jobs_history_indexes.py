# 062_jobs_history_indexes.py
# Indexes for job history at scale (1500 devices, daily backups) and the daily retention
# cleanup (py/libs/retention.py):
#   backups(devid, created)                   - "has a backup" check of every backup run (was a
#                                               full table scan) and the backup list per device
#   backups(created)                          - backup list by date, retention
#   command_execution_log(executed_at)        - retention (date range over all devices)
#   command_execution_log(raw_storage_path)   - /api/backup/list joins backups to their runs
#   task_results(external_id), (created)      - snippet results page, retention
#   pro_sequence_history(created)             - retention (Pro table, only when it exists)
#   config_versions(previous_version_id),     - deleting a config version (retention, or a
#   command_execution_log(version_id)           device) clears these ON DELETE SET NULL
#                                               references: without an index that is a full
#                                               table scan per version (minutes for 2000
#                                               versions with 1M log rows). Retention does not
#                                               prune versions until these exist.
#
# Plain CREATE INDEX (the migrator runs in a transaction): on a large command_execution_log
# writes to that table wait until the index is built (usually seconds, a few minutes for
# millions of rows). Run it outside backup windows.

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_backups_devid_created ON public.backups (devid, created DESC)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_backups_created ON public.backups (created)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_executed_at ON public.command_execution_log (executed_at)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_raw_path ON public.command_execution_log (raw_storage_path)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_cv_previous ON public.config_versions (previous_version_id)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_ce_version ON public.command_execution_log (version_id)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_task_results_external ON public.task_results (external_id)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_task_results_created ON public.task_results (created)")
    migrator.sql("""
        DO $$
        BEGIN
            IF to_regclass('public.pro_sequence_history') IS NOT NULL THEN
                CREATE INDEX IF NOT EXISTS idx_seq_history_created ON public.pro_sequence_history (created);
            END IF;
        END $$
    """)


def rollback(migrator, database, fake=False, **kwargs):
    for name in ("idx_backups_devid_created", "idx_backups_created", "idx_ce_executed_at", "idx_ce_raw_path",
                 "idx_task_results_external", "idx_task_results_created", "idx_seq_history_created",
                 "idx_cv_previous", "idx_ce_version"):
        migrator.sql("DROP INDEX IF EXISTS public.{}".format(name))
