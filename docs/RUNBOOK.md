# Runbook

## Health
- GET /health should return {"status":"ok"}
- GET /metrics should expose Prometheus metrics

## Common Tasks
- Reload models: POST /models/reload (auth required)
- Import KB: POST /kb/import (auth required)
- Delete user data: DELETE /data (auth required)

## Troubleshooting
- High latency: check `chat_latency_seconds` and upstream models
- 429 errors: increase RATE_LIMIT_PER_MINUTE or verify client behavior
- No KB answers: verify KB JSONL exists and `kb_entries` > 0

## Rollback
- Redeploy previous image tag
- Validate /health and smoke test endpoints