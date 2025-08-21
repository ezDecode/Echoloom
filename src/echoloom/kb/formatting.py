from dataclasses import dataclass
from typing import List, Dict, Any
from .retrieval import KBEntry


@dataclass
class FormattedAnswer:
	answer: str
	source_id: str
	snippet: str
	score: float
	suggested_followups: List[str]


def format_answer(entry: KBEntry, score: float) -> FormattedAnswer:
	return FormattedAnswer(
		answer=entry.answer,
		source_id=entry.id,
		snippet=entry.question,
		score=score,
		suggested_followups=["Anything else I can help with?"],
	)


def to_json(answer: FormattedAnswer) -> Dict[str, Any]:
	return {
		"answer": answer.answer,
		"source_id": answer.source_id,
		"snippet": answer.snippet,
		"score": answer.score,
		"suggested_followups": answer.suggested_followups,
	}