#!/usr/bin/python
# -*- coding: utf-8 -*-

# logsetup.py: log format of every MikroWizard process (web workers, spoolers, mules, CLI)
# MikroWizard.com , Mikrotik router management solution
#
# No Flask here: the mules call init_logging() themselves, so they log the same way in the
# free tier (before, they only got logging through the Pro import of libs.webutil, and
# INFO lines were lost without it). libs.webutil calls it with its request filter (user + ip).
# Idempotent: the first call configures, later calls do nothing.
# Level: PYSRV_LOG_LEVEL; unset = INFO with DEV_MODE=true, WARNING (warnings / errors only) otherwise.

import logging
import os

import config

_DONE_ATTR = "_mikrowizard_logging"


class ColorFormatter(logging.Formatter):
    """Colorize warnings and errors"""

    def format(self, rec):
        if rec.levelno == logging.WARNING:
            rec.msg = "\033[93m{}\033[0m".format(rec.msg)
        elif rec.levelno in (logging.ERROR, logging.CRITICAL):
            rec.msg = "\033[91m{}\033[0m".format(rec.msg)
        return logging.Formatter.format(self, rec)


class WorkerContextFilter(logging.Filter):
    """uid / ip fields of the log format for processes without web requests."""

    def filter(self, record):
        record.ip = "local" if config.IS_LOCAL_DEV else ""
        record.uid = "  -WORKER"  # background worker
        return True


def log_level():
    """PYSRV_LOG_LEVEL (config.LOG_LEVEL) when set; otherwise INFO in the dev environment
    (DEV_MODE=true) and WARNING everywhere else. An unknown name means WARNING."""
    name = str(getattr(config, "LOG_LEVEL", "") or "").upper()
    if not name:
        name = "INFO" if os.getenv("DEV_MODE") == "true" else "WARNING"
    level = logging.getLevelName(name)
    return level if isinstance(level, int) else logging.WARNING


def init_logging(context_filter=None):
    """Console logging with the MikroWizard format at log_level().
    context_filter fills the uid / ip fields (default: background worker)."""
    root = logging.getLogger()
    if getattr(root, _DONE_ATTR, False):
        return
    prefix = "PROD " if config.IS_PRODUCTION else ""
    format = prefix+"%(levelname)3.3s %(uid)s@%(ip)s %(asctime)s %(filename)s %(message)s"
    dfmt = "%d%m%y-%H:%M:%S"
    logging.basicConfig(level=log_level(), format=format, datefmt=dfmt)
    root.setLevel(log_level())       # also when a handler existed before (basicConfig did nothing)

    formatter = ColorFormatter(format, datefmt=dfmt)

    # custom log data: userid + ip addr
    f = context_filter or WorkerContextFilter()
    for handler in logging.root.handlers:
        handler.addFilter(f)
        handler.setFormatter(formatter) # remove if coloring not wanted

    if config.PYSRV_LOG_SQL:
        logging.getLogger('peewee').setLevel(logging.DEBUG)
    setattr(root, _DONE_ATTR, True)
