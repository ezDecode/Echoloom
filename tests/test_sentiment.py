from echoloom.nlp.sentiment import analyze_sentiment


def test_sentiment_positive_and_negative():
	pos = analyze_sentiment("I love this! Great job.")
	neg = analyze_sentiment("I hate this. Terrible service.")
	assert pos.label == "positive"
	assert neg.label == "negative"