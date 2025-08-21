# Sentiment Model Selection

- Approach: VADER (rule-based) via `vaderSentiment`
- Rationale: Lightweight, no GPU, good for short chat messages
- Categories: negative, neutral, positive
- Thresholds (VADER defaults):
  - compound >= 0.05 -> positive
  - compound <= -0.05 -> negative
  - otherwise -> neutral

Integration:
- Expose `analyze_sentiment(text) -> (label, score)`
- Adapter includes label and score in `NLPResult`