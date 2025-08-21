# Echoloom Architecture

## Components

- API Service (FastAPI): handles REST endpoints and routing
- NLP Engine: intent recognition, NER, small talk (pluggable adapters)
- KB Service: FAQ storage, retrieval, ranking
- Sentiment: detection and tone adjustment
- Data Stores: Postgres/Mongo for structured data; optional vector store
- Cache & RL: Redis for caching and rate-limiting

## High-level Diagram (Mermaid)

```mermaid
flowchart LR
  Client -->|HTTP| API[FastAPI]
  API --> NLP[Adapter Layer]
  NLP --> Intent[Intent Classifier]
  NLP --> NER[Entity Extractor]
  NLP --> SmallTalk[Small Talk]
  NLP --> Sentiment
  API --> KB[KB Retrieval]
  KB -->|Embeddings/BM25| Storage[(DB/VectorStore)]
  API --> Cache[(Redis)]
```

## Sequence: Chat Request

```mermaid
sequenceDiagram
  participant U as User
  participant A as API
  participant N as NLP Adapter
  participant K as KB
  U->>A: POST /chat {message}
  A->>N: analyze(message)
  N-->>A: intents, entities, sentiment
  A->>K: retrieve(message, intents)
  K-->>A: ranked answers
  A-->>U: response with tone + attribution
```

## Component Responsibilities

- API: auth, rate-limits, validation, orchestration
- NLP Adapter: unified interface for models and rules
- KB: ingestion, retrieval, ranking, confidence thresholds
- Sentiment: classification and tone rules
- Observability: structured logs, metrics, healthchecks