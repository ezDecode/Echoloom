# NLP Data Schema

## Intent Training Data (JSON Lines)
Each line is a JSON object:

- text: user utterance string
- intent: canonical intent id (snake_case)
- entities: optional list of {type, value, start, end}
- metadata: optional key-value object

Example:
```json
{"text": "What are your hours?", "intent": "faq_hours", "entities": [], "metadata": {"lang": "en"}}
```

## CSV Format (for convenience)
- Columns: text, intent
- Optional extra columns are ignored by ingestion.

## File Locations
- Samples: `data/samples/intent_samples.csv`
- Output: `data/samples/intent_samples.jsonl`

## Entity Types (initial)
- person, org, location, date, time, email, phone, product