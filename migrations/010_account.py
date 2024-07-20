# 015_account.py

def migrate(migrator, database, fake=False, **kwargs):


    migrator.sql("""CREATE TABLE account(
        id serial PRIMARY KEY NOT NULL,
        devid bigint REFERENCES devices(id),
        message text,
        action text,
        section text,
        username text,
        config text,
        address text,
        ctype text,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE account""")

