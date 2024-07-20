# 027_permissions.py

def migrate(migrator, database, fake=False, **kwargs):


    migrator.sql("""CREATE TABLE permissions(
        id serial PRIMARY KEY NOT NULL,
        name text,
        perms text,
        created  timestamp not null default CURRENT_TIMESTAMP,
        modified  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE permissions""")

