# Echoloom API

## Auth
- Header: `x-api-key: <key>`

## Endpoints
- GET /health
- POST /kb/import
- POST /models/reload
- POST /chat
- DELETE /data
- GET /metrics

## Schemas
- ChatRequest: { message: string }
- ChatResponse: { intent, entities[], sentiment, sentiment_score, language, answer, source_id?, snippet?, suggested_followups[] }

## Python SDK snippet
```python
import httpx
r = httpx.post("http://localhost:8000/chat", headers={"x-api-key":"dev-key-123"}, json={"message":"hello"})
print(r.json())
```

## JS snippet
```js
const r = await fetch("http://localhost:8000/chat", {method: "POST", headers: {"x-api-key": "dev-key-123", "content-type":"application/json"}, body: JSON.stringify({message: "hello"})});
console.log(await r.json());
```