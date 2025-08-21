from __future__ import annotations
from typing import Dict, Any
import httpx


class EcholoomClient:
	def __init__(self, base_url: str = "http://localhost:8000", api_key: str = "dev-key-123") -> None:
		self.base_url = base_url.rstrip("/")
		self.api_key = api_key

	def _headers(self) -> Dict[str, str]:
		return {"x-api-key": self.api_key}

	def chat(self, message: str) -> Dict[str, Any]:
		r = httpx.post(f"{self.base_url}/chat", headers=self._headers(), json={"message": message}, timeout=15)
		r.raise_for_status()
		return r.json()

	def kb_import(self) -> Dict[str, Any]:
		r = httpx.post(f"{self.base_url}/kb/import", headers=self._headers(), timeout=30)
		r.raise_for_status()
		return r.json()

	def delete_data(self) -> Dict[str, Any]:
		r = httpx.delete(f"{self.base_url}/data", headers=self._headers(), timeout=15)
		r.raise_for_status()
		return r.json()