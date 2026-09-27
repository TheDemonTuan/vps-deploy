#!/usr/bin/env python3
"""Isolated HTTP slot, RTK, and loopback TLS proxy for disposable runner."""
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

active = 0
active_lock = threading.Lock()
mode = sys.argv[1]


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if mode == 'rtk' and self.path == '/filter':
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_json({'protocolVersion': 1, 'content': body['content'].splitlines()[0]})
        else:
            self.send_error(404)

    def do_GET(self):
        global active
        if mode == 'tls':
            stale = Path(sys.argv[5]) / 'stale-public-ack'
            if stale.exists() and self.path.startswith('/api/health'):
                data = json.dumps({'ok': True, 'deployment_slot': 'blue'}).encode()
                self.send_response(200)
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-9Router-Route-Generation', '1' * 32)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            stream = self.path == '/stream'
            connection = http.client.HTTPConnection('127.0.0.1', int(sys.argv[4]), timeout=180 if stream else 10)
            try:
                connection.request('GET', self.path, headers={'Host': self.headers['Host'], 'Cache-Control': self.headers.get('Cache-Control', 'no-cache')})
                response = connection.getresponse()
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in ('connection', 'transfer-encoding', 'content-length', 'server', 'date'):
                        self.send_header(name, value)
                if stream:
                    self.send_header('Connection', 'close')
                    self.close_connection = True
                else:
                    body = response.read()
                    self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if stream:
                    while chunk := response.read1(65536):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                else:
                    self.wfile.write(body)
            finally:
                connection.close()
            return
        if mode == 'rtk':
            if self.path == '/health':
                self.send_json({'ok': True})
            elif self.path == '/version':
                self.send_json({'protocolVersion': 1})
            else:
                self.send_error(404)
            return
        if self.path.startswith('/api/health'):
            with active_lock:
                count = active
            override = Path('/app/data/health-override')
            signal = override.read_text().strip() if override.exists() else ''
            if signal == 'unknown':
                count, known = None, False
            elif signal == 'negative':
                count, known = -1, True
            elif signal == 'boolean':
                count, known = True, True
            else:
                known = True
            self.send_json({'ok': True, 'deployment_slot': os.environ['DEPLOY_SLOT'], 'instance_id': socket.gethostname() + '-1', 'active_requests_known': known, 'active_requests': count, 'active_streams': count if type(count) is int and count >= 0 else 0, 'active_non_stream': 0, 'oldest_active_ms': 10 if count else None})
        elif self.path == '/stream':
            with active_lock:
                active += 1
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(b'data: ready\n\n')
                self.wfile.flush()
                self.close_connection = True
                until = time.monotonic() + 120
                while time.monotonic() < until and not Path('/app/data/release-stream').exists():
                    time.sleep(.1)
                self.wfile.write(b'data: end\n\n')
                self.wfile.flush()
            finally:
                with active_lock:
                    active -= 1
        else:
            self.send_error(404)


if mode == 'tls':
    httpd = ThreadingHTTPServer(('127.0.0.1', 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[2], sys.argv[3])
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
else:
    httpd = ThreadingHTTPServer(('0.0.0.0', 8080 if mode == 'rtk' else 20128), Handler)
httpd.serve_forever()
