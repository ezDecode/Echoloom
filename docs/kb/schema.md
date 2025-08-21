# KB Schema & Storage Choice

## Document Schema
- id: unique string id (e.g., faq_hours)
- question: short question/title
- answer: factual answer text
- tags: list of strings (topics, keywords)
- intent: optional canonical intent id to link with NLP
- metadata: optional key-value fields

## File Formats
- CSV: columns [id,question,answer,tags,intent]
- JSONL: one object per line with the schema above

## Storage Choice (prototype)
- Start with in-memory TF-IDF index using scikit-learn for local/staging
- Optionally migrate to PostgreSQL full-text or a vector DB as data grows

## Paths
- Source: `data/kb/faq.csv`
- Normalized JSONL: `data/kb/faq.jsonl`