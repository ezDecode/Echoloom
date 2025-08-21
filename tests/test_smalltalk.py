from echoloom.nlp.smalltalk import smalltalk_response


def test_smalltalk_responses():
	assert smalltalk_response("smalltalk_greeting") is not None
	assert smalltalk_response("smalltalk_thanks") is not None
	assert smalltalk_response("unknown_intent") is None