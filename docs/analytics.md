# Analytics & Metrics

## Exposed Metrics
- requests_total: total HTTP requests
- intent_requests_total{intent}: requests per top intent
- chat_latency_seconds: histogram of /chat latency
- kb_entries: current number of KB entries

## Example PromQL
- Rate of chats by intent: `sum(rate(intent_requests_total[5m])) by (intent)`
- P95 latency: `histogram_quantile(0.95, sum(rate(chat_latency_seconds_bucket[5m])) by (le))`
- Error rate: `sum(rate(requests_total{code=~"5.."}[5m])) / sum(rate(requests_total[5m]))`