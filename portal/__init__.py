from flask import Flask
import json

from portal.database import Database

__author__ = 'Jeremy Van <jeremyvan@uchicago.edu>'

app = Flask(__name__)
app.config.from_pyfile('portal.conf')

database = Database(app)

import portal.views
