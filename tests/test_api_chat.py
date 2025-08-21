from fastapi.testclient import TestClient
from echoloom.app import create_app


def test_chat_and_kb_import_flow(tmp_path, monkeypatch):
	app = create_app()
	client = TestClient(app)
	# Set API_KEYS for auth
	monkeypatch.setenv("API_KEYS", "test-key")
	monkeypatch.setenv("KB_CSV_PATH", "data/kb/faq.csv")
	monkeypatch.setenv("KB_JSONL_PATH", str(tmp_path / "faq.jsonl"))

	# import KB (requires auth)
	r = client.post("/kb/import", headers={"x-api-key": "test-key"})
	assert r.status_code == 200
	assert r.json()["imported"] >= 1

	# chat
	r2 = client.post(
		"/chat",
		headers={"x-api-key": "test-key"},
		json={"message": "What are your hours?"},
	)
	assert r2.status_code == 200
	data = r2.json()
	assert data["answer"]
	assert data["intent"]
	assert data["language"]

	# delete data
	r3 = client.delete("/data", headers={"x-api-key": "test-key"})
	assert r3.status_code == 200
	assert r3.json()["status"] == "deleted"