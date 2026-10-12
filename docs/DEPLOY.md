# Deploying BankGuard

The project ships two equivalent entrypoints that share one request-handling module
(`app_core.py`), so local dev and production never drift apart:

- **Local dev**: `python server.py` — a stdlib `http.server` that serves `/check`, `/health`,
  `/api/check`, `/api/health`, and the static `web/` demo UI from one process.
- **Production (Vercel)**: `api/check.py` and `api/health.py` — Python serverless functions
  (Vercel's documented `BaseHTTPRequestHandler`-based runtime) under `/api/*`, with `web/`
  served as static assets via `vercel.json`'s `outputDirectory`.

## Deploy to Vercel

1. Push this repo to GitHub.
2. In the Vercel dashboard: **Add New → Project**, import the repo. Vercel detects
   `api/*.py` as Python Serverless Functions automatically (no framework preset needed —
   pick "Other" if asked) and reads `vercel.json` for the rest.
3. Under **Settings → Environment Variables**, add `GEMINI_API_KEY` (get one at
   [aistudio.google.com/apikey](https://aistudio.google.com/apikey)). Optionally add
   `GEMINI_MODEL` (see `.env.example` for the current verified default) and
   `RATE_LIMIT_PER_MIN`. Never commit these — `vercel.json` carries no secrets, by design.
4. Deploy. Vercel builds `api/check.py` and `api/health.py` as separate functions and serves
   `web/`'s contents as the static site root (via `outputDirectory: "web"` in `vercel.json`).
5. Test:
   ```bash
   curl https://<your-project>.vercel.app/api/health
   curl https://<your-project>.vercel.app/api/check -d '{"message":"Transfer $50 to savings"}'
   ```
   Then open `https://<your-project>.vercel.app/` — the demo UI calls `/api/check` and
   `/api/health` with relative URLs, so it works identically on Vercel and on `localhost:8080`
   without any config change (see `web/app.js`'s `API_BASE`).

No `vercel.json`, or want to configure by hand instead: set the framework preset to "Other",
output directory to `web`, and leave the build command empty (there is no build step — this is
plain HTML/CSS/JS and stdlib Python).

**I could not run an actual Vercel deploy from this sandbox** (no Vercel account access here).
Everything above follows Vercel's current documented Python runtime contract — a top-level
`handler` class per file in `api/`, subclassing `BaseHTTPRequestHandler` — which I verified
against vercel.com/docs/functions/runtimes/python before writing `api/check.py` and
`api/health.py`. Confirm `/api/health` responds correctly on your first real deploy before
relying on it.

## Local dev

```bash
cp .env.example .env    # fill in GEMINI_API_KEY (or leave LLM_PROVIDER=none for rules-only)
python server.py
```

Open `http://localhost:8080`. `server.py` reads `.env` via `bankguard/envfile.py` at startup
(a real environment variable always takes precedence over the file, so this is safe to leave
in place when you later `export` the same vars for a different test).

You can also run `vercel dev` locally if you have the Vercel CLI installed — it should execute
`api/check.py` / `api/health.py` exactly as deployed and serve `web/` the same way
`outputDirectory` does in production. This wasn't verified from this sandbox either (no CLI
installed here); if `vercel dev` behaves differently from `server.py` for you, trust
`vercel dev` as the source of truth for what Vercel actually does, and file that as a gap in
this doc.

## Environment variables

See `.env.example` for the full list with descriptions: `PORT` (local dev only), `BANKGUARD_VERBOSE`,
`LLM_PROVIDER`, `GEMINI_API_KEY`, `GEMINI_MODEL`, `RATE_LIMIT_PER_MIN`.

## What's in place for production use

- **CORS**: `Access-Control-Allow-Origin: *` on every response, `OPTIONS` handled, so the
  demo UI (or any frontend) can call `/api/check` cross-origin if hosted separately.
- **Rate limiting**: a per-IP fixed window on `POST /check` / `/api/check`
  (`RATE_LIMIT_PER_MIN`, default 30 req/min), returns `429` over the limit. **In-memory and
  per-process** — see "What's out of scope" below, this matters more on Vercel than it does
  for `server.py`.
- **Fail-closed firewall**: oversized payloads (>20KB), malformed JSON, internal errors, and
  (for high-risk/money-moving intents) an unreachable or erroring judge all return non-200
  rather than silently allowing a request through.
- **7s total judge timeout budget**: `GeminiJudge` caps the *entire* retry sequence (one
  attempt + one retry on timeout/429) at 7 seconds total, not per call — each attempt gets
  roughly half the remaining budget — so a single `/api/check` invocation stays comfortably
  inside Vercel's 10s function limit even in the hybrid pipeline. Verified against the live
  Gemini API while building this: `gemini-flash-lite-latest` responded in ~1.3–2.3s per call
  under normal load, but a sustained-load eval run did hit real timeouts (see
  `evals/RESULTS.md`'s honest note on that run) — the 7s budget (up from an initial 4s) exists
  specifically because 4s was occasionally too tight.
- **No secret echo**: account numbers are truncated to last-4 before they ever leave
  `bankguard/intent.py`; `Config(verbose=False)` additionally hides rule names, matched text,
  and judge reasoning from callers (set `BANKGUARD_VERBOSE=0` for a production deploy where
  callers shouldn't learn which rule fired).
- **No key ever printed or logged**: `bankguard/envfile.py` and `bankguard/providers/gemini.py`
  only ever reference the key to put it in a request header; errors are logged by exception
  type, never by message/response body that could embed it.

## What's intentionally out of scope for this deploy

- **Rate limiting is per-instance, not global.** `app_core.py`'s `_request_log` is an
  in-memory dict. On `server.py` (one long-running process) that's a real limit. On Vercel,
  each function invocation *can* land on a different, often cold-started, instance — so the
  limiter resets unpredictably and is closer to "soft" than "hard" in production. A real
  multi-instance rate limit needs a shared store (e.g. Upstash Redis, which is the usual
  Vercel-native pairing) — not implemented here.
- **The in-memory judge cache is per-instance too**, for the same reason; it helps within a
  warm instance's lifetime but isn't a shared cache across the fleet.
- **TLS termination**: Vercel terminates TLS for you; the plain-Python `server.py` path has no
  HTTPS of its own (fine for local dev, not for exposing `server.py` directly to the internet).
- **Request logging / observability**: `log_message` is suppressed deliberately (keeps raw
  user text out of access logs); there's no structured logging or metrics export here — see
  `docs/JURY_QA.md` for how we'd add it.
