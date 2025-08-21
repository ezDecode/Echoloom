def adjust_tone(response_text: str, sentiment_label: str) -> str:
	if sentiment_label == "negative":
		return "I'm sorry to hear that. " + response_text
	if sentiment_label == "positive":
		return "Great! " + response_text
	return response_text