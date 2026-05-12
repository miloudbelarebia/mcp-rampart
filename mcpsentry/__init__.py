"""
MCPSentry — The MCP bridge that audits your routes before exposing them to LLMs.

Turn any FastAPI app into an MCP server in one line — with a pre-flight
security audit so you don't accidentally hand LLMs your admin endpoints,
sensitive params, or PII-leaking responses — plus runtime guardrails
that scan every tools/call for prompt-injection patterns.

Quick start:

    from fastapi import FastAPI
    from mcpsentry import MCPSentry

    app = FastAPI()
    bridge = MCPSentry(app)

    # Pre-flight security audit
    report = bridge.audit()
    if report.has_blockers():
        report.print_text()
        raise SystemExit(1)

    # Runtime guardrails on every incoming tools/call
    bridge.enable_guardrails(policy="block")
"""

from mcpsentry.audit import (
    AuditReport,
    Auditor,
    Finding,
    IssueType,
    Severity,
)
from mcpsentry.bridge import MCPSentry
from mcpsentry.injection import (
    Action,
    Confidence,
    InjectionDetector,
    InjectionResult,
    PatternMatch,
)
from mcpsentry.runtime import (
    CallLog,
    Guardrail,
    GuardrailDecision,
    Policy,
)

__version__ = "0.3.0"
__all__ = [
    # Bridge
    "MCPSentry",
    # Audit (v0.2)
    "AuditReport",
    "Auditor",
    "Finding",
    "IssueType",
    "Severity",
    # Injection detection (v0.3)
    "Action",
    "Confidence",
    "InjectionDetector",
    "InjectionResult",
    "PatternMatch",
    # Runtime guardrails (v0.3)
    "CallLog",
    "Guardrail",
    "GuardrailDecision",
    "Policy",
]
