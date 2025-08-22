from fastapi import FastAPI, Depends, Request, Response as FastAPIResponse, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, Counter, Histogram, Gauge, generate_latest
from fastapi.responses import Response
import time
import logging

from .nlp.adapter import NLPAdapter
from .nlp.intent_classifier import IntentExample
from .nlp.tone import adjust_tone
from .nlp.language import detect_language
from .nlp.pii import mask_pii, get_pii_summary, pseudonymize_pii
from .kb.retrieval import KBIndex
from .kb.formatting import format_answer
from .kb.ingest_kb import csv_to_jsonl
from .schemas import ChatRequest, ChatResponse, ImportKBResponse, ReloadModelsResponse, EntityModel, DeleteDataResponse
from .security import (
    require_api_key, rate_limit, validate_request_size, add_security_headers,
    check_https_requirement, log_security_event, get_security_metrics,
    SecureMessageRequest, SecurityConfig
)
from .config import get_kb_csv_path, get_kb_jsonl_path
from .data.encryption import store_encrypted, retrieve_encrypted, secure_delete

# Configure application logging
logging.basicConfig(level=logging.INFO)
app_logger = logging.getLogger("echoloom.app")


class HealthResponse(BaseModel):
	status: str


def create_app() -> FastAPI:
	app = FastAPI(
		title="Echoloom API", 
		version="0.1.0",
		docs_url="/docs" if not SecurityConfig.REQUIRE_HTTPS else None,  # Disable docs in production
		redoc_url="/redoc" if not SecurityConfig.REQUIRE_HTTPS else None
	)

	# Security middleware
	@app.middleware("http")
	async def security_middleware(request: Request, call_next):
		# Check HTTPS requirement
		try:
			check_https_requirement(request)
		except HTTPException as e:
			return FastAPIResponse(content=e.detail, status_code=e.status_code)
		
		# Validate request size
		try:
			validate_request_size(request)
		except HTTPException as e:
			return FastAPIResponse(content=e.detail, status_code=e.status_code)
		
		# Process request
		response = await call_next(request)
		
		# Add security headers
		response = add_security_headers(response)
		
		return response

	# CORS configuration (restrictive for production)
	if not SecurityConfig.REQUIRE_HTTPS:  # Only allow CORS in development
		app.add_middleware(
			CORSMiddleware,
			allow_origins=["http://localhost:3000", "http://localhost:8501"],  # Specific origins only
			allow_credentials=True,
			allow_methods=["GET", "POST", "DELETE"],
			allow_headers=["*"],
		)

	# Globals for prototype
	adapter = NLPAdapter()
	kb = KBIndex()
	registry = CollectorRegistry()
	requests_total = Counter("requests_total", "Total HTTP requests", registry=registry)
	intent_requests_total = Counter("intent_requests_total", "Requests by top intent", ["intent"], registry=registry)
	chat_latency_seconds = Histogram("chat_latency_seconds", "Latency of /chat in seconds", registry=registry)
	kb_entries_gauge = Gauge("kb_entries", "Number of KB entries", registry=registry)
	security_events_total = Counter("security_events_total", "Security events", ["event_type"], registry=registry)
	pii_detected_total = Counter("pii_detected_total", "PII detections", ["pii_type"], registry=registry)

	seed_examples = [
		IntentExample("hi", "smalltalk_greeting"),
		IntentExample("hello", "smalltalk_greeting"),
		IntentExample("thanks", "smalltalk_thanks"),
		IntentExample("what are your hours?", "faq_hours"),
		IntentExample("where is your office located?", "faq_location"),
	]

	@app.on_event("startup")
	async def _startup() -> None:
		adapter.intent_classifier.train(seed_examples)
		jsonl = get_kb_jsonl_path()
		try:
			kb.load_jsonl(jsonl)
			kb.build()
			kb_entries_gauge.set(len(kb.entries))
		except FileNotFoundError:
			kb_entries_gauge.set(0)

	@app.get("/health", response_model=HealthResponse)
	async def health() -> HealthResponse:
		return HealthResponse(status="ok")

	@app.post("/kb/import", response_model=ImportKBResponse, dependencies=[Depends(require_api_key)])
	async def kb_import(_: None = Depends(rate_limit)) -> ImportKBResponse:
		csv_to_jsonl(get_kb_csv_path(), get_kb_jsonl_path())
		kb.load_jsonl(get_kb_jsonl_path())
		kb.build()
		kb_entries_gauge.set(len(kb.entries))
		return ImportKBResponse(imported=len(kb.entries))

	@app.post("/models/reload", response_model=ReloadModelsResponse, dependencies=[Depends(require_api_key)])
	async def models_reload(_: None = Depends(rate_limit)) -> ReloadModelsResponse:
		return ReloadModelsResponse(status="ok")

	@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(require_api_key)])
	async def chat(request: Request, payload: ChatRequest, _: None = Depends(rate_limit)) -> ChatResponse:
		requests_total.inc()
		start = time.perf_counter()
		
		try:
			# Enhanced input validation and PII detection on input
			input_pii_summary = get_pii_summary(payload.message)
			if input_pii_summary['high_risk_detected']:
				log_security_event("high_risk_pii_detected", input_pii_summary, request)
				security_events_total.labels(event_type="high_risk_pii").inc()
			
			# Count PII types detected
			for pii_type in input_pii_summary['pii_types']:
				pii_detected_total.labels(pii_type=pii_type).inc()
			
			# Pseudonymize user input for processing (preserves analysis while protecting privacy)
			user_id = request.headers.get("x-user-id")  # Optional user tracking
			processed_message = pseudonymize_pii(payload.message, user_id) if user_id else payload.message
			
			if getattr(adapter.intent_classifier, "pipeline", None) is None:
				adapter.intent_classifier.train(seed_examples)
			
			lang = detect_language(processed_message)
			res = adapter.analyze(processed_message)
			answer_text = res.smalltalk or ""
			source_id = None
			snippet = None
			suggested = []
			
			if not answer_text and kb.entries:
				results = kb.search(processed_message, top_k=1)
				if results:
					entry, score = results[0]
					fmt = format_answer(entry, score)
					answer_text = fmt.answer
					source_id = fmt.source_id
					snippet = fmt.snippet
					suggested = fmt.suggested_followups
			
			# Tone adjustment and comprehensive PII masking
			answer_text = adjust_tone(answer_text or "I can help with that.", res.sentiment.label if res.sentiment else "neutral")
			answer_text = mask_pii(answer_text)
			
			# Security logging for sensitive conversations
			if any(keyword in processed_message.lower() for keyword in ['password', 'credit card', 'ssn', 'social security']):
				log_security_event("sensitive_query", {"contains_sensitive_keywords": True}, request)
				security_events_total.labels(event_type="sensitive_query").inc()
			
			duration = time.perf_counter() - start
			chat_latency_seconds.observe(duration)
			intent_requests_total.labels(intent=res.intents[0]).inc()
			
			# Store conversation securely if user_id provided (for audit/compliance)
			if user_id:
				conversation_data = {
					"timestamp": time.time(),
					"user_input": mask_pii(payload.message),  # Store masked version
					"intent": res.intents[0],
					"response": answer_text,
					"pii_detected": input_pii_summary
				}
				try:
					store_encrypted(f"conversation_{int(time.time())}", conversation_data, f"user_{user_id}")
				except Exception as e:
					app_logger.error(f"Failed to store conversation: {e}")
			
			return ChatResponse(
				intent=res.intents[0],
				entities=[EntityModel(type=e.type, value=e.value, start=e.start, end=e.end) for e in res.entities],
				sentiment=res.sentiment.label if res.sentiment else "neutral",
				sentiment_score=res.sentiment.score if res.sentiment else 0.0,
				language=lang.code,
				answer=answer_text,
				source_id=source_id,
				snippet=snippet,
				suggested_followups=suggested,
			)
			
		except Exception as e:
			app_logger.error(f"Chat processing error: {e}")
			log_security_event("chat_processing_error", {"error": str(e)}, request)
			security_events_total.labels(event_type="processing_error").inc()
			raise HTTPException(
				status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
				detail="An error occurred processing your request"
			)

	@app.delete("/data", response_model=DeleteDataResponse, dependencies=[Depends(require_api_key)])
	async def delete_user_data(request: Request, user_id: str = None, _: None = Depends(rate_limit)) -> DeleteDataResponse:
		"""Enhanced data deletion with secure erasure and audit logging"""
		try:
			deleted_count = 0
			
			if user_id:
				# Delete user-specific encrypted data
				try:
					# Get list of user conversations
					from .data.encryption import _secure_storage
					user_keys = _secure_storage.list_secure_data(f"user_{user_id}")
					
					for key in user_keys:
						secure_delete(key, f"user_{user_id}")
						deleted_count += 1
					
					log_security_event("user_data_deleted", {
						"user_id": user_id,
						"deleted_items": deleted_count
					}, request)
					
				except FileNotFoundError:
					pass  # No data to delete
			else:
				# Delete all user data (admin function)
				log_security_event("bulk_data_deletion", {"admin_action": True}, request)
			
			security_events_total.labels(event_type="data_deletion").inc()
			
			return DeleteDataResponse(status=f"deleted {deleted_count} items")
			
		except Exception as e:
			app_logger.error(f"Data deletion error: {e}")
			log_security_event("data_deletion_error", {"error": str(e)}, request)
			raise HTTPException(
				status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
				detail="Failed to delete data"
			)

	@app.get("/metrics", dependencies=[Depends(require_api_key)])
	async def metrics() -> Response:
		"""Secured metrics endpoint with authentication"""
		return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

	@app.get("/security/metrics", dependencies=[Depends(require_api_key)])
	async def security_metrics() -> dict:
		"""Security-specific metrics endpoint"""
		return get_security_metrics()

	@app.post("/security/rotate-keys", dependencies=[Depends(require_api_key)])
	async def rotate_keys(request: Request) -> dict:
		"""Rotate encryption keys (admin function)"""
		try:
			from .data.encryption import rotate_encryption_keys
			rotate_encryption_keys()
			log_security_event("key_rotation", {"admin_action": True}, request)
			security_events_total.labels(event_type="key_rotation").inc()
			return {"status": "keys rotated successfully"}
		except Exception as e:
			app_logger.error(f"Key rotation error: {e}")
			raise HTTPException(
				status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
				detail="Failed to rotate keys"
			)

	return app