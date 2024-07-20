
# 002_devices.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE devices(
        id serial PRIMARY KEY NOT NULL,
        name text,
        ip text,
        mac text UNIQUE,
        details text,
        uptime text,
        license text,
        interface text,
        user_name text,
        password text,
        port text,
        update_availble boolean,
        current_firmware text,
        arch text,
        upgrade_availble boolean,
        sensors text,
        router_type text,
        wifi_config text,
        peer_ip text,
        failed_attempt int DEFAULT 0,
        syslog_configured boolean,
        status text NOT NULL DEFAULT 'done',
        firmware_to_install text,
        owner uuid REFERENCES users(id),
        created timestamp not null default CURRENT_TIMESTAMP,
        modified timestamp not null default CURRENT_TIMESTAMP
    )""")

def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE devices""")

