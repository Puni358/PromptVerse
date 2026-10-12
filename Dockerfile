FROM python:3.12-slim

WORKDIR /app

# anthropic is optional (only needed for the hybrid LLM-judge layer), but installed by
# default so ANTHROPIC_API_KEY works out of the box with no image rebuild.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bankguard/ bankguard/
COPY prompts/ prompts/
COPY web/ web/
COPY server.py .

ENV PORT=8080
EXPOSE 8080

# BaseHTTPRequestHandler needs no extra runtime user; run as non-root for defense in depth.
RUN useradd -m bankguard
USER bankguard

CMD ["python", "server.py"]
