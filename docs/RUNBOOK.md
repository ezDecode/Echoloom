# Runbook

## Health
- GET /health should return {"status":"ok"}
- GET /metrics should expose Prometheus metrics

## Common Tasks
- Reload models: POST /models/reload (auth required)
- Import KB: POST /kb/import (auth required)
- Delete user data: DELETE /data (auth required)

## Running Backend
- Local: `make run` (requires `make setup` first)
- Docker: `docker compose up --build api`

## Running UI (Streamlit)
- Local: `make ui` (uses `.env` for API_URL/API_KEY)
- Docker: `make ui-docker` (builds `Dockerfile.streamlit` and runs on 8501)
- UI loads Plus Jakarta Sans, dark theme, badges, and follow-ups

## Troubleshooting
- High latency: check `chat_latency_seconds` and upstream models
- 429 errors: increase RATE_LIMIT_PER_MINUTE or verify client behavior
- No KB answers: verify KB JSONL exists and `kb_entries` > 0 (POST /kb/import)
- UI cannot reach API: ensure API_URL points to backend (`http://api:8000` in compose)

## Rollback
- Redeploy previous image tag
- Validate /health and smoke test endpoints