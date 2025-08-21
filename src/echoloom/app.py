from fastapi import FastAPI, Depends
from pydantic import BaseModel
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, Counter, generate_latest
from fastapi.responses import Response

from .nlp.adapter import NLPAdapter
from .nlp.intent_classifier import IntentExample
from .nlp.tone import adjust_tone
from .kb.retrieval import KBIndex
from .kb.formatting import format_answer, to_json
from .kb.ingest_kb import csv_to_jsonl
from .schemas import ChatRequest, ChatResponse, ImportKBResponse, ReloadModelsResponse, EntityModel
from .security import require_api_key, rate_limit
from .config import get_kb_csv_path, get_kb_jsonl_path


class HealthResponse(BaseModel):
	status: str


def create_app() -> FastAPI:
	app = FastAPI(title="Echoloom API", version="0.1.0")

	# Globals for prototype
	adapter = NLPAdapter()
	kb = KBIndex()
	registry = CollectorRegistry()
	requests_total = Counter("requests_total", "Total HTTP requests", registry=registry)

	seed_examples = [
		IntentExample("hi", "smalltalk_greeting"),
		IntentExample("hello", "smalltalk_greeting"),
		IntentExample("thanks", "smalltalk_thanks"),
		IntentExample("what are your hours?", "faq_hours"),
		IntentExample("where is your office located?", "faq_location"),
	]

	@app.on_event("startup")
	async def _startup() -> None:
		# Seed-train a minimal classifier so /chat works without external training
		adapter.intent_classifier.train(seed_examples)
		# build or rebuild KB index
		jsonl = get_kb_jsonl_path()
		try:
			kb.load_jsonl(jsonl)
			kb.build()
		except FileNotFoundError:
			pass

	@app.get("/health", response_model=HealthResponse)
	async def health() -> HealthResponse:
		return HealthResponse(status="ok")

	@app.post("/kb/import", response_model=ImportKBResponse, dependencies=[Depends(require_api_key)])
	async def kb_import(_: None = Depends(rate_limit)) -> ImportKBResponse:
		csv_to_jsonl(get_kb_csv_path(), get_kb_jsonl_path())
		kb.load_jsonl(get_kb_jsonl_path())
		kb.build()
		return ImportKBResponse(imported=len(kb.entries))

	@app.post("/models/reload", response_model=ReloadModelsResponse, dependencies=[Depends(require_api_key)])
	async def models_reload(_: None = Depends(rate_limit)) -> ReloadModelsResponse:
		# placeholder: in a real system we would load from artifacts
		return ReloadModelsResponse(status="ok")

	@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(require_api_key)])
	async def chat(payload: ChatRequest, _: None = Depends(rate_limit)) -> ChatResponse:
		requests_total.inc()
		# Ensure classifier trained even if startup didn’t run (e.g., tests not using lifespan)
		if getattr(adapter.intent_classifier, "pipeline", None) is None:
			adapter.intent_classifier.train(seed_examples)
		res = adapter.analyze(payload.message)
		answer_text = res.smalltalk or ""
		# query KB if not smalltalk
		source_id = None
		snippet = None
		suggested = []
		if not answer_text and kb.entries:
			results = kb.search(payload.message, top_k=1)
			if results:
				entry, score = results[0]
				fmt = format_answer(entry, score)
				answer_text = fmt.answer
				source_id = fmt.source_id
				snippet = fmt.snippet
				suggested = fmt.suggested_followups
		# tone adjust
		answer_text = adjust_tone(answer_text or "I can help with that.", res.sentiment.label if res.sentiment else "neutral")
		return ChatResponse(
			intent=res.intents[0],
			entities=[EntityModel(type=e.type, value=e.value, start=e.start, end=e.end) for e in res.entities],
			sentiment=res.sentiment.label if res.sentiment else "neutral",
			sentiment_score=res.sentiment.score if res.sentiment else 0.0,
			answer=answer_text,
			source_id=source_id,
			snippet=snippet,
			suggested_followups=suggested,
		)

	@app.get("/metrics")
	async def metrics() -> Response:
		return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

	return app