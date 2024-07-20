
# 030_firmware.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""CREATE TABLE firmware(
        id serial PRIMARY KEY NOT NULL,
        version text NOT NULL,
        location text NOT NULL,
        architecture text NOT NULL,
        sha256 text NOT NULL,
        created  timestamp not null default CURRENT_TIMESTAMP,
        UNIQUE(version, architecture)

    )""")

def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE firmware""")

