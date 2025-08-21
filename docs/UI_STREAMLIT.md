# Streamlit UI

## Install
```bash
. .venv/bin/activate
pip install -e .[ui]
```

## Configure
- API_URL: default http://localhost:8000
- API_KEY: default dev-key-123

## Run
```bash
cd ui
streamlit run streamlit_app.py
```

## Docker Compose
- See docker-compose.yml `ui` service