import re
from dataclasses import dataclass
from typing import List


@dataclass
class Entity:
	type: str
	value: str
	start: int
	end: int


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DATE_RE = re.compile(r"\b(?:\d{1,2}[/-])?\d{1,2}[/-]\d{2,4}\b")
LOCATION_HINTS = ["office", "headquarters", "hq", "address", "located"]


def extract_entities(text: str) -> List[Entity]:
	entities: List[Entity] = []
	for match in EMAIL_RE.finditer(text):
		entities.append(Entity("email", match.group(), match.start(), match.end()))
	for match in DATE_RE.finditer(text):
		entities.append(Entity("date", match.group(), match.start(), match.end()))
	lower_text = text.lower()
	for hint in LOCATION_HINTS:
		idx = lower_text.find(hint)
		if idx != -1:
			entities.append(Entity("location_hint", text[idx : idx + len(hint)], idx, idx + len(hint)))
	return entities