from dataclasses import dataclass
from typing import List, Optional

from .intent_classifier import IntentClassifier
from .ner import extract_entities, Entity
from .smalltalk import smalltalk_response
from .sentiment import analyze_sentiment, SentimentResult


@dataclass
class NLPResult:
	intents: List[str]
	entities: List[Entity]
	sentiment: Optional[SentimentResult] = None
	smalltalk: Optional[str] = None


class NLPAdapter:
	def __init__(self, intent_classifier: Optional[IntentClassifier] = None) -> None:
		self.intent_classifier = intent_classifier or IntentClassifier()

	def analyze(self, text: str) -> NLPResult:
		intent = self.intent_classifier.predict([text])[0]
		entities = extract_entities(text)
		st = smalltalk_response(intent)
		sent = analyze_sentiment(text)
		return NLPResult(intents=[intent], entities=entities, sentiment=sent, smalltalk=st)