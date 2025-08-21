from dataclasses import dataclass
from langdetect import detect


@dataclass
class LanguageDetection:
	code: str


def detect_language(text: str) -> LanguageDetection:
	try:
		code = detect(text)
	except Exception:
		code = "unknown"
	return LanguageDetection(code=code)