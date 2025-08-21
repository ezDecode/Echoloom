# Contributing to Echoloom

- Fork and create feature branches from `develop`.
- Follow the branching model in `docs/BRANCHING.md`.
- Write tests (pytest) and ensure coverage passes locally.
- Follow conventional commits with task IDs, e.g. `feat(M1-T2): add app skeleton`.
- Open a PR to `develop`; include description, screenshots/logs, and checklist.

## Development

- Python 3.11+
- Install: `pip install -e .[dev]`
- Run tests: `pytest -q`
- Lint/format: `ruff check .` and `ruff format .`