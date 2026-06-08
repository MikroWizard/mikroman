#!/usr/bin/python
# -*- coding: utf-8 -*-

# api_scanner.py: API for device scanner in network
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

from flask import request

from libs.db import db_tasks,db_syslog
from libs.webutil import app, login_required,buildResponse,get_myself,get_ip,get_agent
import bgtasks
import json
import logging
log = logging.getLogger("api.scanner")

@app.route('/api/scanner/scan', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def scan_network():
    """Do scan requested network for given ip range to find mikrotik devices"""
    input = request.json
    start=input.get('start',False)
    end=input.get('end',False)
    port=input.get('port')
    ssl=input.get('ssl',False)
    if not port:
        port=8729 if ssl else 8728
    password=input.get('password',False)
    username=input.get('user',False)
    status=db_tasks.scanner_job_status().status

    if not status:
        if start and end and port:
            db_syslog.add_syslog_event(get_myself(), "Scanner","start", get_ip(),get_agent(),json.dumps(input))
            bgtasks.scan_with_ip(start=start,end=end,port=port,password=password,username=username,ssl=ssl,user=get_myself())
            return buildResponse({'status': True},200)
        else:
            return buildResponse({'status': status},200)
    else:
        return buildResponse({'status': status},200)

@app.route('/api/scanner/results', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def scan_resutls():
    """Get scan results including IP scan and bulk add"""
    input = request.json
    tasks=db_tasks.TaskResults
    #Get tasks that is task_type is ip-scan or bulk-add
    tasks=tasks.select().where(tasks.task_type.in_(['ip-scan','bulk-add'])).order_by(tasks.id.desc())
    tasks=list(tasks.dicts())
    #Get task results
    return buildResponse({'status': True,'data':tasks},200)

@app.route('/api/dev/bulk_add', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def bulk_add_devices():
    """Bulk add devices from provided list"""
    input = request.json
    devices = input.get('devices', [])
    
    if not devices or not isinstance(devices, list):
        return buildResponse({'error': 'Invalid device data provided'}, 400)
    
    for device in devices:
        if not all(key in device for key in ['ip', 'username', 'password']):
            return buildResponse({'error': 'Invalid device data provided'}, 400)
    
    import datetime
    task_id = f"bulk_add_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(devices)) % 1000000}"
    
    db_tasks.create_bulk_add_task(task_id)
    db_syslog.add_syslog_event(get_myself(), "Bulk Add", "start", get_ip(), get_agent(), json.dumps(input))
    bgtasks.bulk_add_devices(devices=devices, user=get_myself(), task_id=task_id)
    
    return buildResponse({'taskId': task_id}, 200)

@app.route('/api/dev/bulk_add_status', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def bulk_add_status():
    """Check bulk add task status"""
    input = request.json
    task_id = input.get('taskId', None)
    
    if not task_id:
        return buildResponse({'error': 'Task ID required'}, 400)
    
    try:
        task = db_tasks.get_bulk_add_task(task_id)
        if not task:
            return buildResponse({
                'status': 'failed',
                'message': 'Task not found'
            }, 200)
            
        if task.status:
            return buildResponse({
                'status': 'processing',
                'message': 'Processing devices...',
                'progress': 50
            }, 200)
        
        tasks = db_tasks.TaskResults
        results = tasks.select().where(
            (tasks.task_type == 'bulk-add') & 
            (tasks.info.contains(task_id))
        ).order_by(tasks.id.desc()).limit(1)
        
        if results:
            result = results[0]
            result_data = json.loads(result.result)
            success_count = sum(1 for r in result_data if r.get('added', False))
            failed_count = len(result_data) - success_count
            
            return buildResponse({
                'status': 'completed',
                'success': success_count,
                'failed': failed_count,
                'resultFile': f'/api/dev/bulk_add_csv/{task_id}'
            }, 200)
        else:
            return buildResponse({
                'status': 'failed',
                'message': 'Task not found or failed'
            }, 200)
    except Exception as e:
        return buildResponse({
            'status': 'failed',
            'message': str(e)
        }, 200)

@app.route('/api/dev/bulk_add_results', methods = ['POST'])
@login_required(role='admin',perm={'device':'full'})
def bulk_add_results():
    """Get bulk add task results"""
    input = request.json
    tasks=db_tasks.TaskResults
    tasks=tasks.select().where(tasks.task_type=='bulk-add').order_by(tasks.id.desc())
    tasks=list(tasks.dicts())
    return buildResponse({'status': True,'data':tasks},200)



@app.route('/api/dev/bulk_add_csv/<task_id>', methods = ['GET'])
@login_required(role='admin',perm={'device':'full'})
def bulk_add_csv(task_id):
    """Download bulk add results as CSV"""
    from flask import Response
    import csv
    import io
    
    tasks = db_tasks.TaskResults
    results = tasks.select().where(
        (tasks.task_type == 'bulk-add') & 
        (tasks.info.contains(task_id))
    ).order_by(tasks.id.desc()).limit(1)
    
    if not results:
        return buildResponse({'error': 'Results not found'}, 404)
    
    result_data = json.loads(results[0].result)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP', 'Status', 'Failure Reason'])
    
    for item in result_data:
        status = 'Success' if item.get('added', False) else 'Failed'
        failure = item.get('failures', '') if not item.get('added', False) else ''
        writer.writerow([item['ip'], status, failure])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=bulk_add_results_{task_id}.csv'}
    )
