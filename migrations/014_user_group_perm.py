
# 029_user_group_perm.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""CREATE TABLE user_group_perm_rel(
        id serial PRIMARY KEY NOT NULL,
        group_id serial REFERENCES device_groups(id),
        user_id uuid REFERENCES users(id),
        perm_id serial REFERENCES permissions(id),
        UNIQUE(group_id, user_id)
    )""")



def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE user_group_perm_rel""")

