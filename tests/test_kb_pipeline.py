from pathlib import Path
from echoloom.kb.ingest_kb import csv_to_jsonl
from echoloom.kb.retrieval import KBIndex
from echoloom.kb.formatting import format_answer


def test_kb_ingest_and_retrieval_and_formatting(tmp_path: Path):
	csv_path = tmp_path / "faq.csv"
	jsonl_path = tmp_path / "faq.jsonl"
	csv_path.write_text(
		"id,question,answer,tags,intent\nfaq_hours,What are your hours?,We are open 9am-5pm Monday to Friday.,hours,faq_hours\n",
		encoding="utf-8",
	)
	csv_to_jsonl(str(csv_path), str(jsonl_path))
	index = KBIndex()
	index.load_jsonl(str(jsonl_path))
	index.build()
	results = index.search("When are you open?", top_k=1)
	assert results and results[0][1] > 0
	entry, score = results[0]
	fa = format_answer(entry, score)
	obj = {
		"source_id": fa.source_id,
		"answer": fa.answer,
	}
	assert obj["source_id"] == "faq_hours"
	assert "open" in obj["answer"].lower()