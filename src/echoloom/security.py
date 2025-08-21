import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Header, HTTPException, status

from .config import get_api_keys, get_rate_limit_per_minute


_request_log: Dict[str, Deque[float]] = defaultdict(deque)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
	keys = get_api_keys()
	if not x_api_key or x_api_key not in keys:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def rate_limit(x_api_key: str | None = Header(default=None)) -> None:
	limit = get_rate_limit_per_minute()
	window = 60.0
	now = time.time()
	log = _request_log[x_api_key or "anon"]
	# purge old
	while log and now - log[0] > window:
		log.popleft()
	if len(log) >= limit:
		raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
	log.append(now)