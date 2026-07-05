"""Pydantic request/response schemas for the HTTP layer.

Pydantic is confined to the web boundary; the firewall engine itself uses plain
dataclasses (app/firewall/models.py). This function converts engine Verdicts
into API responses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.firewall.models import Verdict


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="End-user message to the agent.")
    session_id: str | None = Field(default=None, description="Optional client session id.")


class DetectionModel(BaseModel):
    detector: str
    triggered: bool
    score: float
    reason: str
    matches: list[str] = []


class VerdictModel(BaseModel):
    decision: str
    risk_score: float
    reason: str
    detections: list[DetectionModel]


class ChatResponse(BaseModel):
    decision: str = Field(..., description='"allow" or "block".')
    reason: str
    risk_score: float
    answer: str | None = Field(default=None, description="Agent answer, present only when allowed.")
    verdict: VerdictModel


def verdict_to_model(verdict: Verdict) -> VerdictModel:
    data = verdict.to_dict()
    return VerdictModel(**data)
