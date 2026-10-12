# Deploying BankGuard

The server is stdlib Python (`http.server`), binds `0.0.0.0:$PORT`, and serves both the
`/check` + `/health` API and the static demo UI (`web/`) from the same process — one service,
no reverse proxy required.

## Option A — Render (recommended, matches `render.yaml`)

1. Push this repo to GitHub (or GitLab).
2. In the Render dashboard: **New → Blueprint**, point it at the repo. Render reads
   `render.yaml` and creates a `bankguard-firewall` web service from the `Dockerfile`.
3. Set `ANTHROPIC_API_KEY` in the service's **Environment** tab if you want the hybrid
   rules+LLM pipeline (optional — the service works rules-only without it, see
   `docs/ARCHITECTURE.md`). It is declared `sync: false` in `render.yaml` specifically so it
   is never read from a committed file.
4. Deploy. Render builds the Docker image, runs `python server.py`, and health-checks
   `GET /health`.
5. Your public URL is `https://<service-name>.onrender.com`. Open it directly — that serves
   `web/index.html`, which calls `/check` and `/health` on the same origin.

No `render.yaml`? Create the service manually instead: **New → Web Service**, environment
**Docker**, same env vars as above, health check path `/health`.

## Option B — Docker, anywhere

```bash
docker build -t bankguard-firewall .
docker run -p 8080:8080 \
  -e PORT=8080 \
  -e BANKGUARD_VERBOSE=1 \
  -e RATE_LIMIT_PER_MIN=30 \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  bankguard-firewall
```

Open `http://localhost:8080`. This is the same image Render builds, so it's a good way to
reproduce a deploy locally before pushing.

## Option C — Plain Python, no container

```bash
pip install -r requirements.txt   # optional — only needed for the hybrid judge
PORT=8080 ANTHROPIC_API_KEY=... python server.py
```

## Environment variables

See `.env.example` for the full list with descriptions: `PORT`, `BANKGUARD_VERBOSE`,
`ANTHROPIC_API_KEY`, `RATE_LIMIT_PER_MIN`. Copy it to `.env` for local reference — `.env` is
gitignored and `server.py` reads the real environment, not the file, so either `export` the
values yourself or use a tool like `python-dotenv` / your shell's `set -a; source .env; set +a`.

## What's in place for production use

- **CORS**: `Access-Control-Allow-Origin: *` on every response, `OPTIONS` handled, so the
  demo UI (or any frontend) can call `/check` cross-origin.
- **Rate limiting**: a per-IP fixed window on `POST /check` (`RATE_LIMIT_PER_MIN`, default 30
  req/min), returns `429` over the limit. In-memory, so it resets on restart and is per
  instance — fine for a single-instance demo deploy, not a substitute for an edge rate
  limiter (e.g. Render's/Cloudflare's) at real scale.
- **Fail-closed firewall**: oversized payloads (>20KB), malformed JSON, and internal errors
  all return non-200 rather than silently allowing a request through.
- **No secret echo**: account numbers are truncated to last-4 before they ever leave
  `bankguard/intent.py`; `Config(verbose=False)` additionally hides rule names, matched text,
  and judge reasoning from callers (set `BANKGUARD_VERBOSE=0` for a production deploy where
  callers shouldn't learn which rule fired).

## What's intentionally out of scope for this deploy

- **TLS termination**: Render terminates TLS for you; a bare Docker/plain-Python deploy needs
  a reverse proxy (nginx, Caddy) in front if you need HTTPS yourself.
- **Horizontal scaling**: the in-memory rate limiter and single-threaded `HTTPServer` are
  fine for a demo; a multi-instance production deploy would need a shared rate-limit store
  (Redis) and a real WSGI/ASGI server.
- **Request logging / observability**: `log_message` is suppressed deliberately (keeps raw
  user text out of access logs); there's no structured logging or metrics export here — see
  `docs/JURY_QA.md` for how we'd add it.
