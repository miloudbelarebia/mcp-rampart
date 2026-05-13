"""
MCPRampart - Security Audit Module

Pre-flight scanner for routes exposed via MCP. Catches dangerous patterns
BEFORE your API meets a language model:

  - Authentication / admin endpoints exposed by default
  - Destructive HTTP methods (DELETE, PUT, PATCH) without guardrails
  - Parameters named like secrets (password, token, api_key…)
  - Response schemas with PII-like field names
  - Missing docstrings (LLMs will guess and choose the wrong tool)

Usage:
    rampart = MCPRampart(app)
    report = rampart.audit()
    if report.has_blockers():
        report.print_text()
        raise SystemExit(1)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_rampart.bridge import DiscoveredRoute, MCPRampart


# ── Taxonomy ────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Severity of a security finding."""
    CRITICAL = "critical"  # Blocks exposure by default
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(str, Enum):
    """Categories of security issues detected by the auditor."""
    EXPOSED_AUTH = "exposed_auth"
    EXPOSED_ADMIN = "exposed_admin"
    DESTRUCTIVE_METHOD = "destructive_method"
    PII_IN_RESPONSE = "pii_in_response"
    MISSING_DOCSTRING = "missing_docstring"
    SENSITIVE_PARAM_NAME = "sensitive_param_name"
    UNTYPED_PARAMETER = "untyped_parameter"


SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


# ── Data structures ─────────────────────────────────────────────────────


@dataclass
class Finding:
    """A single security finding from the auditor."""
    severity: Severity
    issue: IssueType
    route_path: str
    route_method: str
    message: str
    suggestion: str = ""

    def format_line(self) -> str:
        return (
            f"{SEVERITY_ICON[self.severity]} "
            f"[{self.severity.value.upper():<8}] "
            f"{self.route_method:<6} {self.route_path}  —  {self.message}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "issue": self.issue.value,
            "route_path": self.route_path,
            "route_method": self.route_method,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class AuditReport:
    """Aggregated audit result for an MCPRampart."""
    findings: list[Finding] = field(default_factory=list)
    total_routes: int = 0
    exposed_tools: int = 0

    # ── Counts ──
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def has_blockers(self) -> bool:
        """True if CRITICAL findings should block exposure."""
        return self.critical_count > 0

    # ── Rendering ──
    def format_text(self) -> str:
        if not self.findings:
            return (
                f"🛡️  MCPRampart audit: clean\n"
                f"   {self.exposed_tools} tools from {self.total_routes} routes — no issues found.\n"
            )

        lines = [
            "🛡️  MCPRampart audit report",
            f"   {self.exposed_tools} tools from {self.total_routes} routes",
            f"   🔴 {self.critical_count} critical · 🟠 {self.high_count} high · "
            f"🟡 {self.medium_count} medium · 🔵 {self.low_count} low",
            "",
        ]
        # Sort by severity (critical first)
        severity_order = {s: i for i, s in enumerate(Severity)}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order[f.severity])
        for f in sorted_findings:
            lines.append("   " + f.format_line())
            if f.suggestion:
                lines.append(f"      ↳ {f.suggestion}")
        return "\n".join(lines)

    def print_text(self) -> None:
        print(self.format_text())

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_routes": self.total_routes,
            "exposed_tools": self.exposed_tools,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "has_blockers": self.has_blockers(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Auditor ─────────────────────────────────────────────────────────────


class Auditor:
    """Scans MCPRampart routes for security risks before LLM exposure."""

    # Path heuristics
    AUTH_PATH_PATTERNS = [
        r"/auth(/|$)", r"/login", r"/logout", r"/signin", r"/signout",
        r"/token", r"/oauth", r"/sso", r"/saml", r"/credentials",
    ]
    ADMIN_PATH_PATTERNS = [
        r"/admin(/|$)", r"/internal(/|$)", r"/_/", r"/debug(/|$)",
        r"/dev(/|$)", r"/superuser", r"/root", r"/management",
    ]

    # Field-name heuristics for PII in response schemas
    PII_FIELD_KEYWORDS = [
        "email", "phone", "ssn", "social_security",
        "credit_card", "card_number", "cvv", "cvc",
        "password", "passwd", "pwd", "secret", "private_key",
        "api_key", "session_id", "auth_token",
        "address", "zip_code", "postal_code", "date_of_birth", "dob",
        "passport", "national_id", "tax_id", "iban",
    ]

    # Parameter-name heuristics for sensitive inputs
    SENSITIVE_PARAM_KEYWORDS = [
        "password", "passwd", "secret", "api_key", "auth_token",
        "private_key", "session_id", "csrf",
    ]

    DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}

    def audit(self, rampart: MCPRampart) -> AuditReport:
        """Run a full pre-flight security audit of the rampart."""
        report = AuditReport(
            total_routes=len(rampart.routes),
            exposed_tools=len(rampart.tools),
        )
        for tool in rampart.tools:
            report.findings.extend(self._audit_route(tool.route))
        return report

    # ── Per-route checks ──

    def _audit_route(self, route: DiscoveredRoute) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Auth endpoint exposed → CRITICAL
        if self._matches_patterns(route.path, self.AUTH_PATH_PATTERNS):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                issue=IssueType.EXPOSED_AUTH,
                route_path=route.path,
                route_method=route.method,
                message="Authentication endpoint exposed to LLM clients",
                suggestion=f"Add '{route.path}' to exclude_paths",
            ))

        # 2. Admin/internal endpoint exposed → CRITICAL
        if self._matches_patterns(route.path, self.ADMIN_PATH_PATTERNS):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                issue=IssueType.EXPOSED_ADMIN,
                route_path=route.path,
                route_method=route.method,
                message="Admin / internal endpoint exposed to LLM clients",
                suggestion="Exclude this route from MCP exposure",
            ))

        # 3. Destructive method → MEDIUM (informational guardrail)
        if route.method in self.DESTRUCTIVE_METHODS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                issue=IssueType.DESTRUCTIVE_METHOD,
                route_path=route.path,
                route_method=route.method,
                message=f"Destructive {route.method} — an LLM call can mutate/delete data",
                suggestion="Document the consequences in the docstring; consider requiring confirmation in your handler",
            ))

        # 4. Missing docstring → HIGH (LLM picks tools by description)
        if not (route.description or "").strip():
            findings.append(Finding(
                severity=Severity.HIGH,
                issue=IssueType.MISSING_DOCSTRING,
                route_path=route.path,
                route_method=route.method,
                message="No docstring — an LLM will guess this tool's purpose",
                suggestion="Add a clear docstring or `summary=` to the route decorator",
            ))

        # 5. Sensitive parameter names → HIGH
        for param_name in route.parameters:
            lower = param_name.lower()
            if any(kw in lower for kw in self.SENSITIVE_PARAM_KEYWORDS):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    issue=IssueType.SENSITIVE_PARAM_NAME,
                    route_path=route.path,
                    route_method=route.method,
                    message=f"Parameter '{param_name}' looks like a credential",
                    suggestion="Don't expose authentication flows via MCP — use exclude_paths",
                ))

        # 6. PII in response schema → HIGH
        if route.response_schema:
            pii_fields = self._find_pii_fields(route.response_schema)
            if pii_fields:
                preview = ", ".join(pii_fields[:3])
                more = f" (+{len(pii_fields) - 3} more)" if len(pii_fields) > 3 else ""
                findings.append(Finding(
                    severity=Severity.HIGH,
                    issue=IssueType.PII_IN_RESPONSE,
                    route_path=route.path,
                    route_method=route.method,
                    message=f"Response may leak PII fields: {preview}{more}",
                    suggestion="Mask PII before returning, or restrict this route from MCP exposure",
                ))

        # 7. Untyped query/path parameters → LOW (LLM may send junk)
        untyped = [
            n for n, info in route.parameters.items()
            if info.get("type") == "string" and "default" not in info
        ]
        if len(untyped) >= 3:
            findings.append(Finding(
                severity=Severity.LOW,
                issue=IssueType.UNTYPED_PARAMETER,
                route_path=route.path,
                route_method=route.method,
                message=f"{len(untyped)} parameters fall back to 'string' — LLMs may send malformed inputs",
                suggestion="Annotate parameters with explicit types (int, bool, list[str], Pydantic models)",
            ))

        return findings

    # ── Helpers ──

    @staticmethod
    def _matches_patterns(path: str, patterns: list[str]) -> bool:
        for pat in patterns:
            if re.search(pat, path, re.IGNORECASE):
                return True
        return False

    def _find_pii_fields(self, schema: dict[str, Any], depth: int = 0) -> list[str]:
        """Recursively walk a JSON schema looking for PII-named fields."""
        if depth > 5:
            return []
        found: list[str] = []
        properties = schema.get("properties", {}) or {}
        for field_name, field_schema in properties.items():
            lower = field_name.lower()
            if any(kw in lower for kw in self.PII_FIELD_KEYWORDS):
                found.append(field_name)
            if isinstance(field_schema, dict) and field_schema.get("type") == "object":
                found.extend(self._find_pii_fields(field_schema, depth + 1))
        return found
