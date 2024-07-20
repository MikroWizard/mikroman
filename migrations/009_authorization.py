# 014_authorization.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""CREATE TYPE type_auth AS ENUM (
        'loggedin',
        'loggedout',
        'failed')
    """)

    migrator.sql("""CREATE TABLE auth(
        id serial PRIMARY KEY NOT NULL,
        devid bigint REFERENCES devices(id),
        ltype type_auth,
        ip text,
        by text,
        username text,
        started bigint DEFAULT 0,
        ended bigint DEFAULT 0,
        sessionid text DEFAULT Null,
        message text DEFAULT Null,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE auth""")

