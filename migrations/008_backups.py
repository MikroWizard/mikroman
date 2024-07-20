
# 013_backups.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE backups(
        id serial PRIMARY KEY NOT NULL,
        devid bigint REFERENCES devices(id),
        dir text,
        filesize int,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE backups""")

