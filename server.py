"""Tiny HTTP wrapper (stdlib only) for local dev. Production deploys use the Vercel functions
in api/check.py and api/health.py instead (see docs/DEPLOY.md) — both share the same setup
and request logic via app_core.py, so behaviour never drifts between the two.

    python server.py            # listens on :8080, serves the demo UI at /
    curl -s localhost:8080/check -d '{"message":"Transfer $50 to savings"}'
    curl -s localhost:8080/api/check -d '{"message":"Transfer $50 to savings"}'   # same route

200 => safe, 403 => blocked, 400 => malformed request body.
"""
import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from app_core import PIPELINE_MODE, client_ip, health_body, run_check

WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_CHECK_PATHS = ("/check", "/api/check")
_HEALTH_PATHS = ("/health", "/api/health")


class Handler(BaseHTTPRequestHandler):
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

    def _send_file(self, rel_path: str):
        path = os.path.normpath(os.path.join(WEB_ROOT, rel_path))
        if not path.startswith(WEB_ROOT) or not os.path.isfile(path):
            return self._send(404, {"error": "not_found"})
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path in _HEALTH_PATHS:
            return self._send(200, health_body())
        if self.path == "/" or self.path == "":
            return self._send_file("index.html")
        if self.path in _CHECK_PATHS or self.path.startswith("/api/"):
            return self._send(404, {"error": "not_found"})
        return self._send_file(self.path.lstrip("/"))

    def do_POST(self):
        if self.path not in _CHECK_PATHS:
            return self._send(404, {"error": "not_found"})
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"bankguard listening on :{port} (pipeline={PIPELINE_MODE})")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
