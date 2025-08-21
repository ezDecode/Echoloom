from dataclasses import dataclass
from typing import List, Optional

from .intent_classifier import IntentClassifier
from .ner import extract_entities, Entity
from .smalltalk import smalltalk_response


@dataclass
class NLPResult:
	intents: List[str]
	entities: List[Entity]
	sentiment: Optional[str] = None
	smalltalk: Optional[str] = None


class NLPAdapter:
	def __init__(self, intent_classifier: Optional[IntentClassifier] = None) -> None:
		self.intent_classifier = intent_classifier or IntentClassifier()

	def analyze(self, text: str) -> NLPResult:
		# naive intent prediction (single top label)
		intent = self.intent_classifier.predict([text])[0]
		entities = extract_entities(text)
		st = smalltalk_response(intent)
		return NLPResult(intents=[intent], entities=entities, sentiment=None, smalltalk=st)