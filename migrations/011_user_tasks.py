# 021_user_tasks.py

def migrate(migrator, database, fake=False, **kwargs):


    migrator.sql("""CREATE TABLE user_tasks(
        id serial PRIMARY KEY NOT NULL,
        name text,
        description text,
        dev_ids text,
        snippetid int,
        data text,
        cron text,
        action text,
        task_type text,
        selection_type text,
        desc_cron text,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE user_tasks""")

