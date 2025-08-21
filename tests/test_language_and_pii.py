from echoloom.nlp.language import detect_language
from echoloom.nlp.pii import mask_pii


def test_language_detection():
	code = detect_language("Hello world").code
	assert isinstance(code, str) and len(code) > 0


def test_pii_masking():
	masked = mask_pii("Contact me at user@example.com or +1 555 123 4567")
	assert "***@" in masked
	assert "***-***-****" in masked