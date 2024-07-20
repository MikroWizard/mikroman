import re
from flask import request, jsonify, g
from playhouse.shortcuts import dict_to_model, update_model_from_dict
import os
os.environ["PYSRV_CONFIG_PATH"] = "/conf/server-conf.json"

import sys
# from libs.db import db_device
# from libs.db import db_groups 
# from libs.db import db_tasks
from libs import util
from libs.db import  db_user_tasks
from libs.webutil import app, login_required, get_myself,buildResponse
from functools import reduce
import logging
from cron_descriptor import get_description
import queue
from threading import Thread
try:
    from libs import utilpro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

log = logging.getLogger("api.usertasks")

def backup_devs(devices):
    num_threads = len(devices)
    q = queue.Queue()
    threads = []
    for dev in devices:
        t = Thread(target=util.backup_routers, args=(dev, q))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    res=[]
    for _ in range(num_threads):
        qres=q.get()
        if not qres['state']:
            util.log_alert('backup',dev,'Backup failed')
        res.append(qres)
    return res


def run_snippets(devices,snippet):
    num_threads = len(devices)
    q = queue.Queue()
    threads = []
    for dev in devices:
        t = Thread(target=util.run_snippets, args=(dev, snippet, q))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    res=[]
    for _ in range(num_threads):
        qres=q.get()
        if 'result' in qres and not qres['result']:
            util.log_alert('run_snippet', dev, 'Run Snippet failed')
        res.append(qres)
    return res
if __name__ == '__main__':
    # quick adhoc tests
    logging.basicConfig(level=logging.DEBUG)
    taksid=sys.argv[1]
    #check if taskid is int
    if not taksid.isdigit():
        print("Wrong Task ID")
        exit()
    utask=db_user_tasks.UserTasks.get_utask_by_id(taksid)
    if not utask:
        log.error("No task with this id {}".format(taksid))
        exit()
    #Get user task from db by id
    
    devices=[]
    devices=db_user_tasks.get_task_devices(utask)
    # if task.selection_type == "devices":
    #     devids=task.dev_ids.split(",")
    #     devices=list(db_device.get_devices_by_id2(devids))
    # else:
    #     for group in task.dev_groups.split(","):
    #         if not group.isdigit():
    #             continue
    #         devices=db_groups.devs2(group)
    
    # task=utaks.select().where(utaks.id == taksid).get()
    if utask.task_type == "backup":
        log.error("TASK TYPE BACKUP")
        res=backup_devs(devices=devices)
    elif utask.task_type == "snippet":
        log.error("TASK TYPE SNIPPET")
        snippet=utask.snippetid.content
        if not snippet:
            log.error("no snippet")
        else:
            res=run_snippets(devices=devices, snippet=snippet)
    elif utask.task_type == "firmware":
        log.error("firmware update")
        if not ISPRO:
            exit()
        res=utilpro.run_firmware_task(utask)

    #log.error(res)
    #[{'id': 3, 'state': False}, {'id': 1, 'state': False}, {'id': 2, 'state': True}]
