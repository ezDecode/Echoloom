import csv
import json
from pathlib import Path
from typing import Dict, Any


def csv_to_jsonl(csv_path: str, jsonl_path: str) -> None:
	csv_file = Path(csv_path)
	jsonl_file = Path(jsonl_path)
	jsonl_file.parent.mkdir(parents=True, exist_ok=True)
	with csv_file.open("r", newline="", encoding="utf-8") as f_in, jsonl_file.open(
		"w", encoding="utf-8"
	) as f_out:
		reader = csv.DictReader(f_in)
		for row in reader:
			obj: Dict[str, Any] = {
				"id": (row.get("id") or "").strip(),
				"question": (row.get("question") or "").strip(),
				"answer": (row.get("answer") or "").strip(),
				"tags": [(row.get("tags") or "").strip()] if row.get("tags") else [],
				"intent": (row.get("intent") or "").strip() or None,
				"metadata": {},
			}
			if obj["id"] and obj["question"] and obj["answer"]:
				f_out.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Normalize FAQ CSV to JSONL")
	parser.add_argument("--csv", default="data/kb/faq.csv")
	parser.add_argument("--out", default="data/kb/faq.jsonl")
	args = parser.parse_args()
	csv_to_jsonl(args.csv, args.out)