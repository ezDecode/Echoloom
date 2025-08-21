from fastapi.testclient import TestClient
from echoloom.app import create_app


def test_e2e_conversation_flow(tmp_path, monkeypatch):
	app = create_app()
	client = TestClient(app)
	monkeypatch.setenv("API_KEYS", "e2e-key")
	monkeypatch.setenv("KB_CSV_PATH", "data/kb/faq.csv")
	monkeypatch.setenv("KB_JSONL_PATH", str(tmp_path / "faq.jsonl"))
	monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "3")

	# Import KB
	r = client.post("/kb/import", headers={"x-api-key": "e2e-key"})
	assert r.status_code == 200
	assert r.json()["imported"] >= 1

	# Smalltalk
	r = client.post("/chat", headers={"x-api-key": "e2e-key"}, json={"message": "hello"})
	assert r.status_code == 200
	j = r.json()
	assert j["intent"]
	assert j["answer"]

	# KB question
	r = client.post("/chat", headers={"x-api-key": "e2e-key"}, json={"message": "What are your hours?"})
	assert r.status_code == 200
	j = r.json()
	assert j["source_id"]

	# Rate limit on 4th call
	r = client.post("/chat", headers={"x-api-key": "e2e-key"}, json={"message": "hello again"})
	assert r.status_code == 200
	r = client.post("/chat", headers={"x-api-key": "e2e-key"}, json={"message": "hello again 2"})
	assert r.status_code in (200, 429)

	# Metrics endpoint
	r = client.get("/metrics")
	assert r.status_code == 200
	assert b"requests_total" in r.content