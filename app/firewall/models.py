"""Core data contracts for the firewall engine.

These are deliberately plain-stdlib dataclasses (no Pydantic / FastAPI) so the
security engine stays framework-agnostic and can be imported and tested
anywhere. The web layer (app/schemas.py) maps these to Pydantic models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Decision(StrEnum):
    """Final firewall decision for a request."""

    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class Detection:
    """The result produced by a single detector (heuristic, judge, ...).

    Attributes:
        detector: Name of the detector that produced this result.
        triggered: Whether the detector considers the input suspicious.
        score: Risk score in the range 0.0 (safe) .. 1.0 (certainly malicious).
        reason: Human-readable explanation of the decision.
        matches: Concrete signals that fired (e.g. matched phrases).
    """

    detector: str
    triggered: bool
    score: float
    reason: str
    matches: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Keep scores well-formed regardless of detector implementation.
        self.score = max(0.0, min(1.0, float(self.score)))


@dataclass
class Verdict:
    """The combined outcome of running the full firewall pipeline."""

    decision: Decision
    risk_score: float
    reason: str
    detections: list[Detection] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "risk_score": round(self.risk_score, 4),
            "reason": self.reason,
            "detections": [
                {
                    "detector": d.detector,
                    "triggered": d.triggered,
                    "score": round(d.score, 4),
                    "reason": d.reason,
                    "matches": d.matches,
                }
                for d in self.detections
            ],
        }
