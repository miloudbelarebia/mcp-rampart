"""
MCPRampart — The MCP bridge that audits your routes before exposing them to LLMs.

Turn any FastAPI app into an MCP server in one line — with a pre-flight
security audit so you don't accidentally hand LLMs your admin endpoints,
sensitive params, or PII-leaking responses — plus runtime guardrails
that scan every tools/call for prompt-injection patterns.

Quick start:

    from fastapi import FastAPI
    from mcp_rampart import MCPRampart

    app = FastAPI()
    rampart = MCPRampart(app)

    # Pre-flight security audit
    report = rampart.audit()
    if report.has_blockers():
        report.print_text()
        raise SystemExit(1)

    # Runtime guardrails on every incoming tools/call
    rampart.enable_guardrails(policy="block")
"""

from mcp_rampart.audit import (
    AuditReport,
    Auditor,
    Finding,
    IssueType,
    Severity,
)
from mcp_rampart.bridge import MCPRampart
from mcp_rampart.injection import (
    Action,
    Confidence,
    InjectionDetector,
    InjectionResult,
    PatternMatch,
)
from mcp_rampart.runtime import (
    CallLog,
    Guardrail,
    GuardrailDecision,
    Policy,
)

__version__ = "0.3.2"
__all__ = [
    # Bridge
    "MCPRampart",
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
