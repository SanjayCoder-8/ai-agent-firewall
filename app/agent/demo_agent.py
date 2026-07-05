"""A deliberately tiny demo agent that lives *behind* the firewall.

Its only purpose in Phase 1 is to prove the firewall lets safe traffic through
to a real assistant. It has NO tools yet - tool/action inspection is Phase 2.

Like the judge, the agent is behind an interface with a mock (offline) and a
Bedrock backend, selected via configuration.
"""

from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

from app.config import Config

AGENT_SYSTEM_PROMPT = "You are a helpful, concise assistant."


@runtime_checkable
class Agent(Protocol):
    def respond(self, message: str) -> str: ...


class MockAgent:
    """Offline stand-in agent. Deterministic, no network."""

    def respond(self, message: str) -> str:
        preview = message.strip()
        if len(preview) > 120:
            preview = preview[:120] + "..."
        return (
            "[mock-agent] I received your message and it passed the firewall. "
            f'You said: "{preview}"'
        )


class BedrockAgent:
    """Real assistant backed by Amazon Bedrock (Claude)."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("bedrock-runtime", region_name=self.config.aws_region)
        return self._client

    def respond(self, message: str) -> str:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "temperature": 0.3,
            "system": AGENT_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": message}],
        }
        resp = self._get_client().invoke_model(
            modelId=self.config.bedrock_model_id,
            body=json.dumps(body),
        )
        payload = json.loads(resp["body"].read())
        return payload["content"][0]["text"]


def get_agent(config: Config) -> Agent:
    """Factory: return the configured agent backend."""
    if config.agent_backend == "bedrock":
        return BedrockAgent(config)
    return MockAgent()
