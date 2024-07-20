# 023_snippets.py

def migrate(migrator, database, fake=False, **kwargs):


    migrator.sql("""CREATE TABLE snippets(
        id serial PRIMARY KEY NOT NULL,
        name text,
        description text,
        content text,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE snippets""")

