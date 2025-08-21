# Setup Guide

## Prerequisites
- Python 3.11+
- Docker (optional for container runs)

## Environment
```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .[dev]
cp .env.template .env
```

## Running locally
```bash
uvicorn echoloom.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
```

## Configuration
- API_KEYS: comma-separated keys (default: dev-key-123)
- KB_CSV_PATH, KB_JSONL_PATH: file paths for KB
- RATE_LIMIT_PER_MINUTE: per-key rate limit for /chat

## Testing
```bash
pytest -q --cov=src --cov-report=term-missing
```

## Docker
```bash
docker build -t echoloom:dev .
docker run -p 8000:8000 echoloom:dev
```