import os
import httpx

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "dev-key-123")


def chat(message: str) -> dict:
	r = httpx.post(f"{API_URL}/chat", headers={"x-api-key": API_KEY}, json={"message": message}, timeout=15)
	r.raise_for_status()
	return r.json()