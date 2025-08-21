from dataclasses import dataclass
from typing import Tuple

from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer


@dataclass
class SentimentResult:
	label: str
	score: float


_analyzer = SentimentIntensityAnalyzer()


def analyze_sentiment(text: str) -> SentimentResult:
	scores = _analyzer.polarity_scores(text)
	compound = scores.get("compound", 0.0)
	if compound >= 0.05:
		label = "positive"
	elif compound <= -0.05:
		label = "negative"
	else:
		label = "neutral"
	return SentimentResult(label=label, score=compound)