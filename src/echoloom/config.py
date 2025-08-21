import os
from typing import Set


def get_api_keys() -> Set[str]:
	keys = os.getenv("API_KEYS", "dev-key-123")
	return {k.strip() for k in keys.split(",") if k.strip()}


def get_kb_csv_path() -> str:
	return os.getenv("KB_CSV_PATH", "data/kb/faq.csv")


def get_kb_jsonl_path() -> str:
	return os.getenv("KB_JSONL_PATH", "data/kb/faq.jsonl")


def get_rate_limit_per_minute() -> int:
	try:
		return int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
	except ValueError:
		return 60