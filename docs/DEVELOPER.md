# Echoloom Developer Docs

## Run locally

```bash
uvicorn echoloom.app:create_app --factory --reload
```

## Test

```bash
pytest -q --cov=src --cov-report=term-missing
```