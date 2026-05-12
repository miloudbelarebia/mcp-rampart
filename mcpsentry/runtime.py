"""
MCPSentry - Runtime Guardrails

Once an MCP server is live, every `tools/call` request that arrives from
a language model is, by definition, untrusted input. This module gives
you a single hook to:

  - **Log** every tools/call (tool name + arguments + decision)
  - **Detect** prompt-injection patterns in the arguments
  - **Block** the call when something looks dangerous
  - **Alert** without blocking, if you'd rather observe first

Wire it up once:

    bridge = MCPSentry(app)
    bridge.enable_guardrails(policy="block")

…and the bridge's tools/call handler will route every incoming request
through a Guardrail before executing the route.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from mcpsentry.injection import (
    Action,
    InjectionDetector,
    InjectionResult,
)

logger = logging.getLogger("mcpsentry.runtime")


class Policy(str, Enum):
    """How the guardrail reacts when it spots something."""
    BLOCK = "block"   # Refuse the call when injection is detected
    ALERT = "alert"   # Let it through but log loudly
    LOG = "log"       # Only log (useful for shadow / observability mode)


@dataclass
class GuardrailDecision:
    """Outcome of running the guardrail against one tools/call request."""
    allowed: bool
    policy: Policy
    tool_name: str
    injection: InjectionResult
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy": self.policy.value,
            "tool_name": self.tool_name,
            "reason": self.reason,
            "injection": self.injection.to_dict(),
        }


@dataclass
class CallLog:
    """One audit log entry for a tools/call request."""
    timestamp: float
    tool_name: str
    decision: GuardrailDecision
    duration_ms: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.timestamp,
            "tool_name": self.tool_name,
            "duration_ms": self.duration_ms,
            "decision": self.decision.to_dict(),
        }


class Guardrail:
    """
    Runtime gate for `tools/call` requests.

    Usage:
        guard = Guardrail(policy="block")
        decision = guard.check(tool_name, arguments)
        if not decision.allowed:
            return refuse(...)
    """

    def __init__(
        self,
        *,
        policy: Policy | str = Policy.BLOCK,
        detect_injection: bool = True,
        log_all_calls: bool = True,
        on_block: Optional[Callable[[GuardrailDecision], None]] = None,
        on_alert: Optional[Callable[[GuardrailDecision], None]] = None,
        custom_detector: Optional[InjectionDetector] = None,
        keep_history: int = 100,
    ):
        self.policy = Policy(policy) if isinstance(policy, str) else policy
        self.detect_injection = detect_injection
        self.log_all_calls = log_all_calls
        self.on_block = on_block
        self.on_alert = on_alert
        self.detector = custom_detector or InjectionDetector()
        self.keep_history = keep_history
        self.history: list[CallLog] = []

    # ── Public API ──

    def check(self, tool_name: str, arguments: Any) -> GuardrailDecision:
        """
        Run all configured checks on `arguments`.

        Returns a GuardrailDecision with `allowed=False` if the call
        should be refused under the current policy.
        """
        injection = (
            self.detector.scan(arguments)
            if self.detect_injection
            else InjectionResult()
        )

        decision = self._apply_policy(tool_name, injection)
        self._record(tool_name, decision)
        return decision

    def record_duration(self, tool_name: str, duration_ms: float) -> None:
        """Attach a duration to the most recent log entry for this tool."""
        for entry in reversed(self.history):
            if entry.tool_name == tool_name and entry.duration_ms is None:
                entry.duration_ms = duration_ms
                return

    def recent(self, n: int = 20) -> list[CallLog]:
        """Return the most recent N log entries."""
        return self.history[-n:]

    def stats(self) -> dict[str, int]:
        """Aggregate counters from in-memory history."""
        total = len(self.history)
        blocked = sum(1 for e in self.history if not e.decision.allowed)
        alerted = sum(
            1 for e in self.history
            if e.decision.allowed and e.decision.injection.matches
        )
        clean = total - blocked - alerted
        return {
            "total": total,
            "blocked": blocked,
            "alerted": alerted,
            "clean": clean,
        }

    # ── Internals ──

    def _apply_policy(
        self,
        tool_name: str,
        injection: InjectionResult,
    ) -> GuardrailDecision:
        recommendation = injection.recommend()
        allowed = True
        reason = ""

        if recommendation == Action.BLOCK:
            if self.policy == Policy.BLOCK:
                allowed = False
                reason = (
                    f"Prompt-injection detected "
                    f"(HIGH:{injection.high_count} "
                    f"MEDIUM:{injection.medium_count} "
                    f"LOW:{injection.low_count})"
                )
            elif self.policy == Policy.ALERT:
                allowed = True
                reason = "Prompt-injection detected — alerted but not blocked"
            else:  # LOG
                allowed = True
                reason = "Prompt-injection detected — logged only"
        elif recommendation == Action.WARN:
            allowed = True
            reason = "Suspicious arguments — non-blocking warning"

        return GuardrailDecision(
            allowed=allowed,
            policy=self.policy,
            tool_name=tool_name,
            injection=injection,
            reason=reason,
        )

    def _record(self, tool_name: str, decision: GuardrailDecision) -> None:
        if self.log_all_calls or decision.injection.matches:
            level = (
                logging.WARNING
                if not decision.allowed
                else logging.INFO if decision.injection.matches
                else logging.DEBUG
            )
            logger.log(
                level,
                "tools/call %s — %s — %s",
                tool_name,
                "ALLOW" if decision.allowed else "BLOCK",
                decision.reason or "clean",
            )

        # Trigger user-supplied callbacks
        if not decision.allowed and self.on_block:
            try:
                self.on_block(decision)
            except Exception:
                logger.exception("on_block callback failed")
        elif decision.injection.matches and self.on_alert:
            try:
                self.on_alert(decision)
            except Exception:
                logger.exception("on_alert callback failed")

        # Keep bounded in-memory history
        entry = CallLog(timestamp=time.time(), tool_name=tool_name, decision=decision)
        self.history.append(entry)
        if len(self.history) > self.keep_history:
            self.history = self.history[-self.keep_history :]


# ── Helper: format a blocked-response payload for JSON-RPC ──


def format_blocked_response(decision: GuardrailDecision) -> dict[str, Any]:
    """
    Build the MCP `tools/call` result returned when a guardrail blocks.

    Matches the standard MCP error shape so any client (Claude Desktop,
    Cursor, etc.) renders the rejection cleanly.
    """
    matched = decision.injection.matches[:5]
    detail = "; ".join(
        f"{m.confidence.value} {m.category} @ {m.location}"
        for m in matched
    )
    text = (
        f"🛡️ Blocked by MCPSentry runtime guardrail.\n"
        f"Reason: {decision.reason}\n"
    )
    if detail:
        text += f"Top matches: {detail}\n"
    return {
        "content": [{"type": "text", "text": text}],
        "isError": True,
        "_mcpsentry": decision.to_dict(),
    }
