"""Heuristic (signature-based) prompt-injection detector.

This is the first, cheapest layer of defense: fast regex/keyword patterns for
well-known injection and jailbreak techniques. It runs on every request and
catches the "obvious" majority before we spend money/latency on the LLM judge.

Each signature contributes to a cumulative risk score. Multiple weak signals
combine into a stronger one, but the score is capped at 1.0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.firewall.models import Detection


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern[str]
    weight: float
    description: str


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Known attack signatures. Weights reflect how strongly the pattern indicates
# a genuine attack (0.0 - 1.0). Tune these against the evaluation suite.
SIGNATURES: list[Signature] = [
    Signature(
        "ignore_instructions",
        _c(
            r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instruction|prompt|rule|direction|context)"
        ),
        0.9,
        "Attempts to discard prior instructions.",
    ),
    Signature(
        "reveal_system_prompt",
        _c(
            r"\b(reveal|show me|show|print|repeat|display|output|tell me|give me|what (are|is|were))\b.{0,30}\b(system prompt|initial prompt|initial instructions|internal prompt|hidden instructions|hidden prompt|your instructions|your prompt|your rules|your configuration|your guidelines|the prompt above|prompt that defines|instructions you (were|are))\b"
        ),
        0.85,
        "Attempts to extract the system prompt (qualified target).",
    ),
    Signature(
        "forget_context",
        _c(
            r"\b(ignore|disregard|forget)\b.{0,20}\b(everything|all)\b.{0,30}\b(you were (told|given|instructed)|before|prior|said|above)"
        ),
        0.85,
        "Attempts to wipe conversation context ('forget everything you were told').",
    ),
    Signature(
        "repeat_verbatim",
        _c(r"\brepeat\b.{0,20}\b(everything|all|the text|words)\b.{0,20}\b(above|before|verbatim)"),
        0.75,
        "Attempts to leak preceding context verbatim.",
    ),
    Signature(
        "jailbreak_persona",
        _c(
            r"\b(you are now|act as|pretend to be|from now on you are|you will be)\b.{0,40}\b(dan|do anything now|jailbroken|unfiltered|unrestricted|evil|no rules)"
        ),
        0.85,
        "Classic persona-based jailbreak (DAN and variants).",
    ),
    Signature(
        "developer_mode",
        _c(r"\b(developer mode|debug mode|god mode|sudo mode|admin mode)\b"),
        0.6,
        "Invokes a fake privileged mode.",
    ),
    Signature(
        "bypass_safety",
        _c(
            r"\b(bypass|disable|turn off|remove|ignore|circumvent)\b.{0,25}\b(safety|guardrail|filter|restriction|moderation|content policy|rules)"
        ),
        0.85,
        "Attempts to disable safety controls.",
    ),
    Signature(
        "no_restrictions",
        _c(
            r"\b(no|without any|free of)\b.{0,15}\b(restrictions|limitations|rules|filters|guidelines|ethics)\b"
        ),
        0.55,
        "Claims the model has no restrictions.",
    ),
    Signature(
        "fake_role_markers",
        _c(r"(^|\n)\s*(system|assistant|developer)\s*:\s*"),
        0.6,
        "Injects fake chat role markers to spoof instructions.",
    ),
    Signature(
        "new_instructions",
        _c(
            r"\b(new|updated|revised|real|actual)\b\s+(instruction|instructions|task|directive|system prompt)\b\s*:?"
        ),
        0.65,
        "Tries to inject replacement instructions.",
    ),
    Signature(
        "exfiltration",
        _c(
            r"\b(send|post|upload|exfiltrate|forward|email|transmit)\b.{0,40}\b(https?://|to\s+\S+@|api key|password|secret|token|credential)"
        ),
        0.8,
        "Attempts to exfiltrate data to an external destination.",
    ),
    Signature(
        "encoded_payload",
        _c(
            r"\b(base64|rot13|hex|decode|decrypt)\b.{0,25}\b(this|the following|and (then )?(run|execute|follow))"
        ),
        0.6,
        "Hides an instruction behind an encoding to evade filters.",
    ),
    Signature(
        "long_base64_blob",
        _c(r"[A-Za-z0-9+/]{80,}={0,2}"),
        0.4,
        "Contains a long base64-like blob (possible hidden payload).",
    ),
]


class HeuristicDetector:
    """Signature-based detector. Stateless and cheap."""

    name = "heuristic"

    def __init__(self, signatures: list[Signature] | None = None) -> None:
        self.signatures = signatures if signatures is not None else SIGNATURES

    def detect(self, text: str) -> Detection:
        matched: list[str] = []
        score = 0.0
        for sig in self.signatures:
            if sig.pattern.search(text):
                matched.append(sig.name)
                # Combine signals: each adds its weight against the remaining
                # "headroom", so multiple hits push toward (but never past) 1.0.
                score = score + sig.weight * (1.0 - score)

        if matched:
            reason = "Matched injection signatures: " + ", ".join(matched)
        else:
            reason = "No known injection signatures matched."

        return Detection(
            detector=self.name,
            triggered=bool(matched),
            score=score,
            reason=reason,
            matches=matched,
        )
