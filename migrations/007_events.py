
# 009_events.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE events(
        id bigserial PRIMARY KEY NOT NULL,
        devid bigint REFERENCES devices(id),
        eventtype text,
        comment text,         
        status boolean,
        detail text,
        level text,
        src text,
        fixtime timestamp null default null,
        eventtime timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE events""")

