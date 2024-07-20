# 038_syslogs.py

def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql("""CREATE TABLE syslogs(
        id serial PRIMARY KEY NOT NULL,
        user_id uuid REFERENCES users(id),
        action text,
        section text,
        data text,
        ip text,
        agent text,
        created  timestamp not null default CURRENT_TIMESTAMP
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE syslogs""")


