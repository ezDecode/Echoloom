from dataclasses import dataclass
from pathlib import Path
from typing import List

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import joblib


@dataclass
class IntentExample:
	text: str
	label: str


class IntentClassifier:
	def __init__(self) -> None:
		self.pipeline: Pipeline | None = None

	def build(self) -> Pipeline:
		pipeline = Pipeline(
			steps=[
				("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
				("clf", LogisticRegression(max_iter=1000)),
			]
		)
		self.pipeline = pipeline
		return pipeline

	def train(self, examples: List[IntentExample]) -> None:
		texts = [e.text for e in examples]
		labels = [e.label for e in examples]
		model = self.build()
		model.fit(texts, labels)

	def predict(self, texts: List[str]) -> List[str]:
		if self.pipeline is None:
			raise RuntimeError("Model not trained")
		return list(self.pipeline.predict(texts))

	def save(self, path: str) -> None:
		if self.pipeline is None:
			raise RuntimeError("Model not trained")
		Path(path).parent.mkdir(parents=True, exist_ok=True)
		joblib.dump(self.pipeline, path)

	def load(self, path: str) -> None:
		self.pipeline = joblib.load(path)


def evaluate(texts: List[str], labels: List[str], model: IntentClassifier) -> str:
	preds = model.predict(texts)
	return classification_report(labels, preds, zero_division=0)