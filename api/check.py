"""Vercel Python serverless function: POST /api/check (Vercel's Python runtime maps
api/check.py to that route automatically — see docs/DEPLOY.md). Must define a top-level
class named `handler` subclassing BaseHTTPRequestHandler; that's the runtime's entrypoint
contract, not a naming choice made here.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app_core import client_ip, run_check  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict):
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 20_000:
                return self._send(413, {"error": "payload_too_large"})
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad_request"})
        status, verdict = run_check(body, client_ip(self.headers, self.client_address))
        self._send(status, verdict)

    def log_message(self, *a):  # keep raw user text out of access logs
        pass
