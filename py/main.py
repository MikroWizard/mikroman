#!/usr/bin/python
# -*- coding: utf-8 -*-

# main.py: server main script
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com thanks to Tomi.Mickelsson@iki.fi (RESTPie3)

# register endpoints
from api import api_account
from api import api_dev
from api import api_sysconfig
from api import api_firmware
from api import api_user_tasks
from api import api_logs
from api import api_scanner
from api import api_backups
from api import api_snippet
try:
    from api import api_pro_api
except ImportError:
    pass

import logging
log = logging.getLogger("main")

log.info("Running! http://localhost:8100")

from libs.webutil import app
if app.testing:
    import werkzeug.debug
    app.wsgi_app = werkzeug.debug.DebuggedApplication(app.wsgi_app, True)
# uwsgi-daemon takes over the app...

