# Echoloom Developer Docs

## Run locally

```bash
uvicorn echoloom.app:create_app --factory --reload
```

## Test

```bash
pytest -q --cov=src --cov-report=term-missing
```

## Smoke

- GitHub Action `smoke.yml` builds Docker image and curls /health and /metrics.

## CI

- `ci.yml` installs dev deps, runs ruff, runs pytest with coverage, builds wheel.