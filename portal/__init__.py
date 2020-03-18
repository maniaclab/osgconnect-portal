from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
import json

import logging.handlers
import logging
import sys

__author__ = 'Jeremy Van <jeremyvan@uchicago.edu>'

app = Flask(__name__)
# Enable CSRF protection globally for Flask app
csrf = CSRFProtect(app)
csrf.init_app(app)

if len(sys.argv) > 1:
    try:
        # Try to read config location from .ini file
        config_file = sys.argv[1]
        app.config.from_pyfile(config_file)
        print("Reading config file from VM .ini file")
    except:
        print("Could not read config location from {}".format(sys.argv[1]))
else:
    print("Reading config file from local directory")
    app.config.from_pyfile('portal.conf')

app.url_map.strict_slashes = False

app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
# response.set_cookie('username', 'flask', secure=True, httponly=True, samesite='Lax')


import portal.views
