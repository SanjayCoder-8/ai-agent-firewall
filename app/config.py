"""Runtime configuration for the firewall.

Uses only the standard library so the engine has no hard dependency on
Pydantic. Values are read from environment variables (see .env.example).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    """Firewall configuration.

    Attributes:
        judge_backend: "mock" (offline, default) or "bedrock".
        agent_backend: "mock" (offline, default) or "bedrock".
        aws_region: AWS region for Bedrock calls.
        bedrock_model_id: Bedrock model id used by the judge and agent.
        block_threshold: Combined risk score at/above which we block.
        heuristic_block_threshold: Heuristic score at/above which we block
            immediately without consulting the (slower/costlier) LLM judge.
    """

    judge_backend: str = "mock"
    agent_backend: str = "mock"
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-haiku-20240307-v1:0"
    block_threshold: float = 0.6
    heuristic_block_threshold: float = 0.9

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            judge_backend=os.getenv("FIREWALL_JUDGE_BACKEND", "mock").lower(),
            agent_backend=os.getenv("FIREWALL_AGENT_BACKEND", "mock").lower(),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            bedrock_model_id=os.getenv(
                "FIREWALL_BEDROCK_MODEL_ID",
                "anthropic.claude-3-haiku-20240307-v1:0",
            ),
            block_threshold=_get_float("FIREWALL_BLOCK_THRESHOLD", 0.6),
            heuristic_block_threshold=_get_float("FIREWALL_HEURISTIC_BLOCK_THRESHOLD", 0.9),
        )
