from pathlib import Path
import json
from echoloom.data.ingest_intents import convert_csv_to_jsonl


def test_convert_csv_to_jsonl(tmp_path: Path):
	csv_path = tmp_path / "samples.csv"
	jsonl_path = tmp_path / "samples.jsonl"
	csv_path.write_text("text,intent\nHello,smalltalk_greeting\nThanks!,smalltalk_thanks\n", encoding="utf-8")
	convert_csv_to_jsonl(str(csv_path), str(jsonl_path))
	lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
	assert len(lines) == 2
	obj0 = json.loads(lines[0])
	assert obj0["text"] == "Hello"
	assert obj0["intent"] == "smalltalk_greeting"
	assert obj0["entities"] == []
	assert isinstance(obj0["metadata"], dict)