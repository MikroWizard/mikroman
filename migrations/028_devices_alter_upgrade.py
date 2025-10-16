# 028_user_alter_proxy.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""ALTER TABLE devices
        ADD COLUMN upgrade_device boolean
    """)
    