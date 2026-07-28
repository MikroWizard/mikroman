"""Server database migrate"""
import subprocess
import sys

dir = "/app/"
cmd = "cd {}; PYTHONPATH={}py PYSRV_CONFIG_PATH={} python3 scripts/dbmigrate.py".format(
    dir, dir, "/opt/mikrowizard/server-conf.json")

result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
if result.stdout:
    print(result.stdout)
if result.stderr:
    print(result.stderr, file=sys.stderr)
if result.returncode != 0:
    print(f"Migration FAILED with exit code {result.returncode}", file=sys.stderr)
    sys.exit(result.returncode)
print("Migration script finished successfully.")
