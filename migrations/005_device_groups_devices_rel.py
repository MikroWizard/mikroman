
# 005_device_groups_devices_rel.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE device_groups_devices_rel(
        id serial PRIMARY KEY NOT NULL,
        group_id serial REFERENCES device_groups(id),
        device_id serial REFERENCES devices(id),
        created timestamp not null default CURRENT_TIMESTAMP,
        modified timestamp not null default CURRENT_TIMESTAMP,
        UNIQUE(group_id, device_id)
    )""")



def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE device_groups_devices_rel""")

