import re

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_RE = re.compile(r"\b(?:\+?\d[\d\s-]{7,}\d)\b")


def mask_pii(text: str) -> str:
	masked = EMAIL_RE.sub(r"***@\2", text)
	masked = PHONE_RE.sub("***-***-****", masked)
	return masked