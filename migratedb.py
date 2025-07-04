"""Server database migrate"""
import subprocess

dir ="/"
cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(dir, dir, "conf/server-config.json")
subprocess.Popen(cmd, shell=True)

