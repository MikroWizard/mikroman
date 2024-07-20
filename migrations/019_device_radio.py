# 038_device_radio.py

def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql("""CREATE TABLE device_radio(
        id serial PRIMARY KEY NOT NULL,
        devid bigint REFERENCES devices(id),
        peer_dev_id bigint REFERENCES devices(id),
        data text,
        external_id text,
        mac text,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")

def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("""DROP TABLE device_radio""")


