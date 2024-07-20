"""Server database migrate"""
import subprocess

dir ="/app/"
cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(dir, dir, "/opt/mikrowizard/server-conf.json")
subprocess.Popen(cmd, shell=True)

