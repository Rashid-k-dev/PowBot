# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from sys import exit
import threading

# Gevent monkey-patching (must be done before importing other modules)
from gevent import monkey

from Powroute import runRelease
monkey.patch_all()

import ssl
from flask_migrate import Migrate
from flask_minify import Minify
from gevent.pywsgi import WSGIServer

from apps.config import config_dict
from apps import create_app, db

# WARNING: Don't run with debug turned on in production!
DEBUG = False
get_config_mode = 'Debug' if DEBUG else 'Production'

try:
    app_config = config_dict[get_config_mode.capitalize()]
except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production]')

app = create_app(app_config)
Migrate(app, db)

if not DEBUG:
    Minify(app=app, html=True, js=False, cssless=False)

if DEBUG:
    app.logger.info('DEBUG            = ' + str(DEBUG))
    app.logger.info('Page Compression = ' + ('FALSE' if DEBUG else 'TRUE'))
    app.logger.info('DBMS             = ' + app_config.SQLALCHEMY_DATABASE_URI)
    app.logger.info('ASSETS_ROOT      = ' + app_config.ASSETS_ROOT)

if __name__ == "__main__":
    # Create a secure SSL context

     # Create a secure SSL context
    websocket_thread = threading.Thread(target=runRelease, daemon=True)
    websocket_thread.start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    try:
        context.load_cert_chain(certfile="certificate.crt", keyfile="private.key")
    except Exception as e:
        app.logger.error(f"Error loading SSL certificate: {e}")
        exit(1)

    # Create and start the Gevent WSGI server with SSL
    http_server = WSGIServer(('0.0.0.0', 443), app, ssl_context=context)
    
    app.logger.info("Starting secure WSGI server on port 443...")
    http_server.serve_forever()
