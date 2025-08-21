from echoloom.nlp.intent_classifier import IntentClassifier, IntentExample


def test_intent_classifier_train_predict(tmp_path):
	examples = [
		IntentExample("hi", "smalltalk_greeting"),
		IntentExample("hello", "smalltalk_greeting"),
		IntentExample("thanks", "smalltalk_thanks"),
		IntentExample("thank you", "smalltalk_thanks"),
		IntentExample("what are your hours?", "faq_hours"),
	]
	clf = IntentClassifier()
	clf.train(examples)
	pred = clf.predict(["hello there"])[0]
	assert pred in {"smalltalk_greeting", "smalltalk_thanks", "faq_hours"}

	model_path = tmp_path / "intent_model.joblib"
	clf.save(str(model_path))
	loaded = IntentClassifier()
	loaded.load(str(model_path))
	pred2 = loaded.predict(["thanks so much"])[0]
	assert pred2 in {"smalltalk_greeting", "smalltalk_thanks", "faq_hours"}