"""Server database migrate"""
import subprocess

dir ="/app/"
cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(dir, dir, "/app/real-server-config.json")
subprocess.Popen(cmd, shell=True)

