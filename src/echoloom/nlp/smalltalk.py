from typing import Optional

SMALLTALK_RESPONSES = {
	"smalltalk_greeting": "Hello! How can I help you today?",
	"smalltalk_thanks": "You're welcome!",
}


def smalltalk_response(intent: str) -> Optional[str]:
	return SMALLTALK_RESPONSES.get(intent)