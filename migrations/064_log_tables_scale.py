# 064_log_tables_scale.py
# Log tables at scale (1500 devices, syslog bursts). Backward compatible: no data is changed,
# every step is idempotent and skipped when the table / column / index is already as wanted.
#
# 1. account.id INTEGER -> BIGINT (+ its sequence). account gets one row per config change of
#    every device and was missed by 047_bigint_logs; at the INT max (2,147,483,647) every insert
#    would fail. Widening keeps all existing ids. No foreign keys reference account.id.
#    NOTE: rewrites the table under an exclusive lock (seconds for millions of rows); syslog
#    writes wait meanwhile and the syslog mule retries them - nothing is lost.
# 2. Any BIGINT column whose sequence is still "AS integer" (e.g. task_results.id): the sequence
#    would stop at the INT max although the column is BIGINT. Metadata only, no rewrite.
# 3. Indexes for the syslog write path, the log pages, device delete and retention:
#      auth(devid, username, started)  - logout -> open login match, RADIUS login window
#      auth(devid, started)            - Terminal Gateway login check (was a 24 h scan of all devices)
#      account(devid, created)         - account log per device, device delete
#      account(created)                - account log by date, retention
#      events(devid, eventtime)        - events per device (incl. resolved), device delete
#      events(eventtime)               - events by date, retention
#
# Plain CREATE INDEX (the migrator runs in a transaction): writes to these tables wait until
# each index is built (seconds; a few minutes for tens of millions of rows). Run off-peak.

def migrate(migrator, database, fake=False, **kwargs):
    if fake:
        return
    migrator.sql("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_schema = 'public' AND table_name = 'account'
                         AND column_name = 'id' AND data_type = 'integer') THEN
                ALTER TABLE public.account ALTER COLUMN id TYPE BIGINT;
            END IF;
        END $$
    """)
    # After step 1 account.id is BIGINT, so this also widens account_id_seq. ALTER SEQUENCE ... AS
    # BIGINT raises MAXVALUE to the BIGINT max (it was the INT max) and keeps the current value.
    migrator.sql("""
        DO $$
        DECLARE r record;
        BEGIN
            FOR r IN
                SELECT s.oid::regclass AS seq
                FROM pg_class s
                JOIN pg_namespace n ON n.oid = s.relnamespace
                JOIN pg_sequence ps ON ps.seqrelid = s.oid
                JOIN pg_depend dp ON dp.objid = s.oid AND dp.classid = 'pg_class'::regclass
                                 AND dp.refclassid = 'pg_class'::regclass AND dp.deptype IN ('a', 'i')
                JOIN pg_attribute a ON a.attrelid = dp.refobjid AND a.attnum = dp.refobjsubid
                WHERE s.relkind = 'S' AND n.nspname = 'public'
                  AND ps.seqtypid = 'integer'::regtype AND a.atttypid = 'bigint'::regtype
            LOOP
                -- string concatenation, not format(): psycopg2 reads a percent sign as a parameter placeholder
                EXECUTE 'ALTER SEQUENCE ' || r.seq::text || ' AS BIGINT';
            END LOOP;
        END $$
    """)
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_auth_devid_user_started ON public.auth (devid, username, started)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_auth_devid_started ON public.auth (devid, started)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_account_devid_created ON public.account (devid, created)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_account_created ON public.account (created)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_events_devid_eventtime ON public.events (devid, eventtime)")
    migrator.sql("CREATE INDEX IF NOT EXISTS idx_events_eventtime ON public.events (eventtime)")


def rollback(migrator, database, fake=False, **kwargs):
    # Ids stay BIGINT: narrowing back could fail (or need a rewrite) once ids pass the INT max,
    # and BIGINT is fully compatible with the old code.
    for name in ("idx_auth_devid_user_started", "idx_auth_devid_started", "idx_account_devid_created",
                 "idx_account_created", "idx_events_devid_eventtime", "idx_events_eventtime"):
        migrator.sql("DROP INDEX IF EXISTS public.{}".format(name))
