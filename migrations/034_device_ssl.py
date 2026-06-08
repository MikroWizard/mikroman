# 034_device_ssl.py

def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql("""ALTER TABLE devices
        ADD COLUMN ssl boolean DEFAULT false
    """)

def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("""ALTER TABLE devices
        DROP COLUMN ssl
    """)
