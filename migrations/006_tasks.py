
# 006_tasks.py

def migrate(migrator, database, fake=False, **kwargs):

    # an example class for demonstrating CRUD...

    migrator.sql("""CREATE TABLE tasks(
        id serial PRIMARY KEY NOT NULL,
        signal int UNIQUE,
        name text,
        starttime timestamp not null default CURRENT_TIMESTAMP,
        endtime timestamp not null default CURRENT_TIMESTAMP,
        status boolean
    )""")



def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE tasks""")

