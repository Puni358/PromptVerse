"""Shared setup used by both the local dev server (server.py) and the Vercel serverless
functions (api/check.py, api/health.py), so the two entrypoints can't drift apart.

Loads .env (local dev only — Vercel injects real env vars directly in production, and
load_dotenv() never overwrites an already-set variable), builds the Firewall instances once
per process, and implements the per-IP rate limiter and /check request/response shape.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from bankguard import Config, Firewall
from bankguard.envfile import load_dotenv
from bankguard.judge import build_judge

load_dotenv(Path(__file__).resolve().parent / ".env")

VERBOSE = os.environ.get("BANKGUARD_VERBOSE", "1") == "1"
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "30"))
RATE_WINDOW_SECONDS = 60.0

JUDGE = build_judge()
PIPELINE_MODE = "hybrid" if JUDGE is not None else "rules_only"
FW = Firewall(Config(verbose=VERBOSE), judge=JUDGE)
FW_STRICT = Firewall(Config(verbose=VERBOSE, strict_intent=True), judge=JUDGE)

# Per-IP fixed window of request timestamps for /check. Best-effort and per-process: on a
# single long-running server.py instance this is a real rate limit; on Vercel, each
# serverless invocation may land on a different (and ephemeral) instance, so this table
# resets often and the limit is closer to "soft" than "hard" — see docs/DEPLOY.md.
_request_log: dict[str, deque] = defaultdict(deque)


def rate_limited(ip: str) -> bool:
    now = time.monotonic()
    log = _request_log[ip]
    cutoff = now - RATE_WINDOW_SECONDS
    while log and log[0] < cutoff:
        log.popleft()
    if len(log) >= RATE_LIMIT_PER_MIN:
        return True
    log.append(now)
    return False


def client_ip(headers, client_address) -> str:
    """Prefers X-Forwarded-For (set by Vercel's edge) over the raw socket address, which on a
    serverless platform is usually a proxy, not the real client."""
    fwd = headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return client_address[0]


def run_check(body: dict, ip: str) -> tuple[int, dict]:
    """Shared POST /check logic. Returns (http_status, response_body)."""
    if rate_limited(ip):
        return 429, {"error": "rate_limited",
                      "message": f"Max {RATE_LIMIT_PER_MIN} requests/minute per client"}
    msg, source = body.get("message"), body.get("source", "user")
    if source not in ("user", "document", "tool", "web"):
        source = "document"  # unknown origin => treat as untrusted
    strict = bool(body.get("strict", False))
    fw = FW_STRICT if strict else FW
    verdict = fw.check(msg, source=source)
    if verdict.get("code") == "service_unavailable":
        return 503, verdict
    return (200 if verdict["status"] == "safe" else 403), verdict


def health_body() -> dict:
    return {"status": "ok", "pipeline": PIPELINE_MODE}
