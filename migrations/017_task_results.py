# 017_permissions.py

def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql("""CREATE TABLE task_results(
        id serial PRIMARY KEY NOT NULL,
        task_type text,
        result text,
        info text,
        external_id int,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE task_results""")

