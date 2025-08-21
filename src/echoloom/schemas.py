from pydantic import BaseModel, Field
from typing import List, Optional, Any


class ChatRequest(BaseModel):
	message: str = Field(..., min_length=1)


class EntityModel(BaseModel):
	type: str
	value: str
	start: int
	end: int


class ChatResponse(BaseModel):
	intent: str
	entities: List[EntityModel]
	sentiment: str
	sentiment_score: float
	answer: str
	source_id: Optional[str] = None
	snippet: Optional[str] = None
	suggested_followups: List[str] = []


class ImportKBResponse(BaseModel):
	imported: int


class ReloadModelsResponse(BaseModel):
	status: str
	info: Any | None = None