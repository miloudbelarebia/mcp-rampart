"""
MCPSentry — The MCP bridge that audits your routes before exposing them to LLMs.

Turn any FastAPI app into an MCP server with a single line — and get a
pre-flight security audit so you don't accidentally hand LLMs your admin
endpoints, sensitive params, or PII-leaking responses.

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
"""

from mcpsentry.audit import (
    AuditReport,
    Auditor,
    Finding,
    IssueType,
    Severity,
)
from mcpsentry.bridge import MCPSentry

__version__ = "0.2.0"
__all__ = [
    "MCPSentry",
    "AuditReport",
    "Auditor",
    "Finding",
    "IssueType",
    "Severity",
]
