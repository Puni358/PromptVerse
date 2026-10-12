"""Minimal stdlib .env loader (no python-dotenv dependency).

Parses simple KEY=VALUE lines, skips blanks/comments, strips matching quotes. Never logs or
prints values. Existing environment variables always win — a .env file only fills in what
isn't already set (so a real deployment's dashboard-set env vars are never shadowed by a
stray .env file shipped by accident).
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> int:
    """Sets os.environ for any KEY=VALUE line in `path` not already in the environment.
    Returns the number of variables set. Silently does nothing if the file doesn't exist."""
    p = Path(path)
    if not p.is_file():
        return 0
    count = 0
    for raw_line in p.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            count += 1
    return count
