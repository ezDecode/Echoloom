from echoloom.nlp.tone import adjust_tone


def test_adjust_tone_prefixes():
	assert adjust_tone("Thanks for reaching out.", "negative").startswith("I'm sorry")
	assert adjust_tone("Glad to help.", "positive").startswith("Great!")
	assert adjust_tone("Okay.", "neutral") == "Okay."