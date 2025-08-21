from dataclasses import dataclass
from typing import List, Tuple
import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class KBEntry:
	id: str
	question: str
	answer: str
	tags: List[str]
	intent: str | None


class KBIndex:
	def __init__(self) -> None:
		self.entries: List[KBEntry] = []
		self.vectorizer: TfidfVectorizer | None = None
		self.matrix = None

	def load_jsonl(self, path: str) -> None:
		self.entries = []
		with Path(path).open("r", encoding="utf-8") as f:
			for line in f:
				obj = json.loads(line)
				self.entries.append(
					KBEntry(
						id=obj["id"],
						question=obj["question"],
						answer=obj["answer"],
						tags=obj.get("tags", []),
						intent=obj.get("intent"),
					)
				)

	def build(self) -> None:
		corpus = [e.question + " \n " + e.answer for e in self.entries]
		self.vectorizer = TfidfVectorizer(ngram_range=(1, 2))
		self.matrix = self.vectorizer.fit_transform(corpus)

	def search(self, query: str, top_k: int = 5) -> List[Tuple[KBEntry, float]]:
		if self.vectorizer is None or self.matrix is None:
			raise RuntimeError("Index not built")
		q_vec = self.vectorizer.transform([query])
		scores = cosine_similarity(q_vec, self.matrix)[0]
		idx_and_score = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)[
			:top_k
		]
		return [(self.entries[i], float(s)) for i, s in idx_and_score]