
# 003_sysconfig.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE sysconfig(
        id serial PRIMARY KEY NOT NULL,
        key text UNIQUE,
        value text,
        created_by uuid REFERENCES users(id),
        created timestamp not null default CURRENT_TIMESTAMP,
        modified timestamp not null default CURRENT_TIMESTAMP
    )""")

def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE sysconfig""")

