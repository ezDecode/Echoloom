import csv
import json
from pathlib import Path
from typing import Dict, Any


def convert_csv_to_jsonl(csv_path: str, jsonl_path: str) -> None:
	"""Convert a CSV file with columns [text,intent] to a JSONL file.

	Each JSONL line: {"text": str, "intent": str, "entities": [], "metadata": {}}
	"""
	csv_file = Path(csv_path)
	jsonl_file = Path(jsonl_path)
	jsonl_file.parent.mkdir(parents=True, exist_ok=True)
	
	with csv_file.open("r", newline="", encoding="utf-8") as f_in, jsonl_file.open(
		"w", encoding="utf-8"
	) as f_out:
		reader = csv.DictReader(f_in)
		for row in reader:
			text = (row.get("text") or "").strip()
			intent = (row.get("intent") or "").strip()
			if not text or not intent:
				continue
			obj: Dict[str, Any] = {
				"text": text,
				"intent": intent,
				"entities": [],
				"metadata": {},
			}
			f_out.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Convert intent CSV to JSONL")
	parser.add_argument("--csv", default="data/samples/intent_samples.csv")
	parser.add_argument("--out", default="data/samples/intent_samples.jsonl")
	args = parser.parse_args()
	convert_csv_to_jsonl(args.csv, args.out)