from echoloom.nlp.intent_classifier import IntentClassifier, IntentExample
from echoloom.nlp.adapter import NLPAdapter


def test_adapter_analyze_pipeline():
	examples = [
		IntentExample("hi", "smalltalk_greeting"),
		IntentExample("hello", "smalltalk_greeting"),
		IntentExample("thanks", "smalltalk_thanks"),
	]
	clf = IntentClassifier()
	clf.train(examples)
	adapter = NLPAdapter(clf)
	res = adapter.analyze("hello there")
	assert res.intents
	assert isinstance(res.entities, list)
	# when greeting, smalltalk should be present
	assert res.smalltalk is not None