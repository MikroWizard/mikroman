
# 004_device_groups.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE device_groups(
        id serial PRIMARY KEY NOT NULL,
        name text,
        owner uuid REFERENCES users(id),
        created timestamp not null default CURRENT_TIMESTAMP,
        modified timestamp not null default CURRENT_TIMESTAMP
    )""")



def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE device_groups""")

