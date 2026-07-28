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
from api import api_executions
from api import api_pam
try:
    from api import api_pro_api
    from api import api_pro_api2
    from api import api_proxy
    from api import api_snippet_pro
    from api import wireguard_api_pro
    from api import api_customer_pro
    from api import api_alerts_pro
    from libs.db import db_ai_chat_pro
    from api import api_terminal_pro
    from api import api_non_mikrotik_pro
    from api import api_policy_pro
    from api import api_config_versions_pro
    from api import api_config_versions
except ImportError as _e:
    import logging as _logging
    _logging.getLogger("main").warning(f"Pro module import failed (running in free mode): {_e}")

import logging
log = logging.getLogger("main")
 
log.info("Running! http://localhost:8100")

from libs.webutil import app
if app.testing:
    import werkzeug.debug
    app.wsgi_app = werkzeug.debug.DebuggedApplication(app.wsgi_app, True)
# uwsgi-daemon takes over the app...

