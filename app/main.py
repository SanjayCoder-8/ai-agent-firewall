"""FastAPI proxy - the entry point users' traffic flows through.

    POST /chat   -> run the firewall; if allowed, forward to the demo agent.
    GET  /health -> liveness + active backends.

This is the only module that depends on FastAPI/Pydantic. The security engine
underneath is framework-agnostic.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from app.agent.demo_agent import get_agent
from app.config import Config
from app.firewall.pipeline import FirewallPipeline
from app.schemas import ChatRequest, ChatResponse, verdict_to_model

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

config = Config.from_env()
pipeline = FirewallPipeline(config)
agent = get_agent(config)

app = FastAPI(
    title="AI Agent Firewall",
    version="0.1.0",
    description="Phase 1: prompt-injection input filter in front of an AI agent.",
)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "judge_backend": config.judge_backend,
        "agent_backend": config.agent_backend,
        "block_threshold": config.block_threshold,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    verdict = pipeline.inspect(req.message)
    verdict_model = verdict_to_model(verdict)

    if verdict.is_blocked:
        # Do NOT forward blocked input to the agent.
        return ChatResponse(
            decision=verdict.decision.value,
            reason=verdict.reason,
            risk_score=round(verdict.risk_score, 4),
            answer=None,
            verdict=verdict_model,
        )

    answer = agent.respond(req.message)
    return ChatResponse(
        decision=verdict.decision.value,
        reason=verdict.reason,
        risk_score=round(verdict.risk_score, 4),
        answer=answer,
        verdict=verdict_model,
    )
