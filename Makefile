PY=python
PIP=$(PY) -m pip

.PHONY: setup test run lint build docker ui ui-docker

setup:
	$(PIP) install -U pip
	$(PIP) install -e .[dev]

run:
	uvicorn echoloom.app:create_app --factory --reload

ui:
	$(PIP) install -e .[ui]
	cd ui && streamlit run streamlit_app.py

test:
	pytest -q --cov=src --cov-report=term-missing

lint:
	ruff check .

build:
	$(PY) -m build

docker:
	docker build -t echoloom:dev .

ui-docker:
	docker compose up --build ui