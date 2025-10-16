# 028_user_alter_proxy.py

def migrate(migrator, database, fake=False, **kwargs):
    migrator.sql("""ALTER TABLE tasks ADD COLUMN task_id text""")
    migrator.sql("""ALTER TABLE tasks DROP CONSTRAINT tasks_signal_key""")
    migrator.sql("""ALTER TABLE tasks ADD CONSTRAINT tasks_signal_task_id_key UNIQUE (signal, task_id)""")
    
def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql("""ALTER TABLE tasks DROP CONSTRAINT tasks_signal_task_id_key""")
    migrator.sql("""ALTER TABLE tasks ADD CONSTRAINT tasks_signal_key UNIQUE (signal)""")
    migrator.sql("""ALTER TABLE tasks DROP COLUMN task_id""")