"""Tests for the pre-flight audit module."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from mcp_rampart import (
    AuditReport,
    Auditor,
    Finding,
    IssueType,
    MCPRampart,
    Severity,
)


# ── Smoke ──────────────────────────────────────────────────────────────


def test_safe_app_passes_audit_with_no_blockers(safe_app):
    rampart = MCPRampart(safe_app)
    report = rampart.audit()
    assert isinstance(report, AuditReport)
    assert not report.has_blockers()
    # No CRITICAL on a deliberately clean app
    assert report.critical_count == 0


def test_risky_app_blocks_on_critical(risky_app):
    rampart = MCPRampart(
        risky_app,
        # bypass the default exclude_paths so the risky routes go through
        include_paths=["/*"],
        exclude_paths=[],
    )
    report = rampart.audit()
    assert report.has_blockers()
    assert report.critical_count >= 2  # auth + admin


# ── Each individual check has a test ──────────────────────────────────


def test_audit_detects_exposed_auth():
    app = FastAPI()
    @app.post("/api/auth/login")
    async def login():
        """Login."""
        return {}
    rampart = MCPRampart(app, include_paths=["/*"], exclude_paths=[])
    report = rampart.audit()
    issues = {f.issue for f in report.findings}
    assert IssueType.EXPOSED_AUTH in issues


def test_audit_detects_exposed_admin():
    app = FastAPI()
    @app.get("/api/admin/users")
    async def admin():
        """Admin."""
        return {}
    rampart = MCPRampart(app, include_paths=["/*"], exclude_paths=[])
    report = rampart.audit()
    assert any(f.issue == IssueType.EXPOSED_ADMIN for f in report.findings)


def test_audit_detects_missing_docstring():
    app = FastAPI()
    @app.get("/api/no_docs")
    async def no_docs():
        return {}
    rampart = MCPRampart(app)
    report = rampart.audit()
    assert any(f.issue == IssueType.MISSING_DOCSTRING for f in report.findings)


def test_audit_detects_sensitive_param_name():
    app = FastAPI()
    @app.post("/api/items")
    async def create(password: str):
        """Create."""
        return {}
    rampart = MCPRampart(app)
    report = rampart.audit()
    assert any(f.issue == IssueType.SENSITIVE_PARAM_NAME for f in report.findings)


def test_audit_detects_pii_in_response():
    class _Out(BaseModel):
        id: int
        email: str
        phone: str

    app = FastAPI()

    @app.get("/api/items", response_model=_Out)
    async def listing():
        """Lists items."""
        return _Out(id=1, email="x@x", phone="0")
    rampart = MCPRampart(app)
    report = rampart.audit()
    pii = [f for f in report.findings if f.issue == IssueType.PII_IN_RESPONSE]
    assert pii, "expected PII finding for response_model with email/phone"


def test_audit_detects_destructive_method():
    app = FastAPI()
    @app.delete("/api/items/{i}")
    async def rm(i: int):
        """Remove."""
        return {}
    rampart = MCPRampart(app)
    report = rampart.audit()
    assert any(f.issue == IssueType.DESTRUCTIVE_METHOD for f in report.findings)
    # MEDIUM, not CRITICAL — destructive verbs don't block by default
    assert not any(
        f.issue == IssueType.DESTRUCTIVE_METHOD and f.severity == Severity.CRITICAL
        for f in report.findings
    )


def test_audit_detects_untyped_parameters():
    app = FastAPI()
    @app.get("/api/search")
    async def s(a, b, c, d):
        """Search."""
        return {}
    rampart = MCPRampart(app)
    report = rampart.audit()
    assert any(f.issue == IssueType.UNTYPED_PARAMETER for f in report.findings)


# ── Report API ─────────────────────────────────────────────────────────


def test_report_to_dict_is_json_serialisable():
    import json
    app = FastAPI()
    @app.post("/api/auth/login")
    async def login():
        """Login."""
        return {}
    report = MCPRampart(app, include_paths=["/*"], exclude_paths=[]).audit()
    d = report.to_dict()
    s = json.dumps(d)
    assert "has_blockers" in d
    assert d["has_blockers"] is True
    parsed = json.loads(s)
    assert parsed == d


def test_report_print_text_includes_severity_glyphs(capsys, risky_app):
    rampart = MCPRampart(risky_app, include_paths=["/*"], exclude_paths=[])
    rampart.audit().print_text()
    out = capsys.readouterr().out
    assert "🔴" in out
