import os
import httpx

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "dev-key-123")


def set_api_config(api_url: str | None = None, api_key: str | None = None) -> None:
	global API_URL, API_KEY
	if api_url:
		API_URL = api_url
	if api_key:
		API_KEY = api_key


def chat(message: str) -> dict:
	r = httpx.post(
		f"{API_URL}/chat",
		headers={"x-api-key": API_KEY},
		json={"message": message},
		timeout=15,
	)
	r.raise_for_status()
	return r.json()