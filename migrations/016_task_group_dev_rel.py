# 032_task_group_dev_rel.py

def migrate(migrator, database, fake=False, **kwargs):

    migrator.sql("""CREATE TABLE task_group_dev_rel(
        id serial PRIMARY KEY NOT NULL,
        utask_id serial REFERENCES user_tasks(id) ,
        group_id bigint  NULL REFERENCES device_groups(id) default null,
        device_id bigint  NULL REFERENCES devices(id) default null,
        UNIQUE(utask_id, group_id , device_id)
    )""")


def rollback(migrator, database, fake=False, **kwargs):

    migrator.sql("""DROP TABLE task_group_dev_rel""")
