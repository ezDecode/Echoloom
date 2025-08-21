PY=python
PIP=$(PY) -m pip

.PHONY: setup test run lint build docker

setup:
	$(PIP) install -U pip
	$(PIP) install -e .[dev]

run:
	uvicorn echoloom.app:create_app --factory --reload

test:
	pytest -q --cov=src --cov-report=term-missing

lint:
	ruff check .

build:
	$(PY) -m build

docker:
	docker build -t echoloom:dev .