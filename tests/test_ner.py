from echoloom.nlp.ner import extract_entities


def test_extract_email_and_date_and_location_hint():
	text = "Email me at user@example.com before 12/31/2025 at your office."
	ents = extract_entities(text)
	types = [e.type for e in ents]
	assert "email" in types
	assert "date" in types
	assert "location_hint" in types