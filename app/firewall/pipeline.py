"""The firewall pipeline: orchestrates detectors into a single Verdict.

Strategy (defense in depth, cost-aware):
  1. Run the cheap heuristic detector first.
  2. If heuristics are highly confident it's an attack, block immediately and
     skip the (slower, costlier) LLM judge.
  3. Otherwise consult the judge and combine the two signals.
  4. Block when the combined risk score meets the configured threshold.

Combining rule: we take the MAX of the detector scores. A firewall should be
conservative - if any competent detector is confident, that's enough. This is
easy to reason about and to explain in a review.
"""

from __future__ import annotations

import logging

from app.config import Config
from app.firewall.heuristics import HeuristicDetector
from app.firewall.llm_judge import Judge, get_judge
from app.firewall.models import Decision, Detection, Verdict

logger = logging.getLogger("firewall.pipeline")


class FirewallPipeline:
    def __init__(
        self,
        config: Config,
        heuristic: HeuristicDetector | None = None,
        judge: Judge | None = None,
    ) -> None:
        self.config = config
        self.heuristic = heuristic or HeuristicDetector()
        self.judge = judge or get_judge(config)

    def inspect(self, text: str) -> Verdict:
        """Run the pipeline on a single input string and return a Verdict."""
        detections: list[Detection] = []

        # --- Layer 1: heuristics (always) ---
        h = self.heuristic.detect(text)
        detections.append(h)

        # Early block: heuristics are confident enough on their own.
        if h.score >= self.config.heuristic_block_threshold:
            verdict = Verdict(
                decision=Decision.BLOCK,
                risk_score=h.score,
                reason=("Blocked by heuristics (high confidence, judge skipped): " + h.reason),
                detections=detections,
            )
            self._log(text, verdict)
            return verdict

        # --- Layer 2: LLM judge (only when heuristics are inconclusive) ---
        j = self.judge.evaluate(text)
        detections.append(j)

        risk = max(h.score, j.score)
        blocked = risk >= self.config.block_threshold
        decision = Decision.BLOCK if blocked else Decision.ALLOW

        if blocked:
            top = h if h.score >= j.score else j
            reason = f"Blocked (risk={risk:.2f} >= {self.config.block_threshold:.2f}). {top.reason}"
        else:
            reason = f"Allowed (risk={risk:.2f} < {self.config.block_threshold:.2f})."

        verdict = Verdict(
            decision=decision,
            risk_score=risk,
            reason=reason,
            detections=detections,
        )
        self._log(text, verdict)
        return verdict

    def _log(self, text: str, verdict: Verdict) -> None:
        # Foundation for the future attack dashboard (Phase 4). We log a
        # truncated preview only - never the full untrusted payload at INFO.
        preview = text[:80].replace("\n", " ")
        logger.info(
            "decision=%s risk=%.2f matches=%s preview=%r",
            verdict.decision.value,
            verdict.risk_score,
            [m for d in verdict.detections for m in d.matches],
            preview,
        )
