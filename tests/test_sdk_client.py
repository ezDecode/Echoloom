from fastapi.testclient import TestClient
from echoloom.app import create_app
from echoloom.sdk.client import EcholoomClient


def test_sdk_client_chat_and_import(monkeypatch):
	app = create_app()
	client = TestClient(app)
	monkeypatch.setenv("API_KEYS", "sdk-key")

	# monkeypatch SDK to use our TestClient
	sdk = EcholoomClient(base_url="http://testserver", api_key="sdk-key")
	def post(url, headers=None, json=None, timeout=None):
		return client.post(url, headers=headers, json=json)
	def delete(url, headers=None, timeout=None):
		return client.delete(url, headers=headers)
	monkeypatch.setattr("httpx.post", post)
	monkeypatch.setattr("httpx.delete", delete)

	imp = sdk.kb_import()
	assert imp["imported"] >= 0
	res = sdk.chat("hello")
	assert res["answer"]
	delr = sdk.delete_data()
	assert delr["status"] == "deleted"