"""
MCPRampart - Prompt-Injection Detector

Pattern-based detector for prompt-injection attempts hidden inside the
arguments of an MCP `tools/call` request.

Detection is intentionally simple and explainable: a curated set of regex
patterns, each tagged with confidence (HIGH/MEDIUM/LOW). A match returns
an `InjectionResult` with the score, matched patterns, and a recommended
action (block / warn / allow).

This is *defence in depth*, not a silver bullet. Combine with:
- MCPRampart.audit() — pre-flight surface review
- Your existing auth / rate-limit / WAF
- Application-level argument validation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Pattern


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Action(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


# ── Pattern catalogue ───────────────────────────────────────────────────
# Tuples: (regex, confidence, category, human label)

_RAW_PATTERNS: list[tuple[str, Confidence, str, str]] = [
    # === HIGH confidence — unambiguous override attempts ===
    (
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+|the\s+|any\s+|previous\s+|prior\s+|above\s+|earlier\s+)+(?:instructions?|prompts?|rules?|messages?|directives?|system\s+prompt)",
        Confidence.HIGH, "instruction_override",
        "Tries to override prior instructions",
    ),
    (
        r"\byou\s+are\s+now\s+(?:a|an|the|in)\b",
        Confidence.HIGH, "role_override",
        "Tries to switch the model's role",
    ),
    (
        r"\b(?:developer|admin|root|debug|god|jailbreak|dan)\s+mode\b",
        Confidence.HIGH, "mode_override",
        "References a privileged mode",
    ),
    (
        r"<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>",
        Confidence.HIGH, "control_token",
        "Embeds chat-template control tokens",
    ),
    (
        r"\[\[\s*(?:system|admin|root)\s*\]\]",
        Confidence.HIGH, "system_marker",
        "Embeds a system-impersonation marker",
    ),
    (
        r"\bSYSTEM\s*:\s*(?:you|do|execute|run|now|always|never)",
        Confidence.HIGH, "system_impersonation",
        "Impersonates a system message",
    ),

    # === MEDIUM confidence — strongly suspicious ===
    (
        r"\bsystem\s+(?:prompt|instructions?|rules?)\b",
        Confidence.MEDIUM, "system_reference",
        "References the system prompt by name",
    ),
    (
        r"\bact\s+as\s+(?:a|an|the)\s+\w+",
        Confidence.MEDIUM, "role_play",
        "Asks the model to act as a different role",
    ),
    (
        r"\bpretend\s+(?:to\s+be|you(?:'re|\s+are)|that\s+you)",
        Confidence.MEDIUM, "role_play",
        "Asks the model to pretend",
    ),
    (
        r"\b(?:reveal|show|tell\s+me|print|output)\s+(?:your|the)\s+(?:instructions?|prompt|rules?|system|original)",
        Confidence.MEDIUM, "extraction",
        "Tries to extract the system prompt or rules",
    ),
    (
        r"\brepeat\s+(?:everything|all|your)\s+(?:above|prior|previous)\b",
        Confidence.MEDIUM, "extraction",
        "Asks the model to repeat the prompt above",
    ),
    (
        r"\bbegin\s+(?:new|fresh|the)?\s*(?:session|conversation)\s+(?:as|with)\b",
        Confidence.MEDIUM, "session_hijack",
        "Tries to start a new session as someone else",
    ),

    # === LOW confidence — suspicious but possibly benign ===
    (
        r"\b(?:send|post|upload|export|exfiltrate)\s+(?:your|all|the)\s+(?:data|info|context|tokens?|secrets?|keys?)\b",
        Confidence.LOW, "exfiltration",
        "Asks the model to send out sensitive data",
    ),
    (
        r"<script\b[^>]*>",
        Confidence.LOW, "xss_payload",
        "Contains an HTML <script> tag",
    ),
    (
        r"(?:^|\s)(?:curl|wget|fetch)\s+https?://",
        Confidence.LOW, "remote_fetch",
        "Includes a command that fetches an external URL",
    ),
    (
        r"\b(?:base64|atob|btoa)\s*[\(:]",
        Confidence.LOW, "obfuscation",
        "Uses base64-style obfuscation",
    ),
]


# Pre-compile once
_COMPILED: list[tuple[Pattern[str], Confidence, str, str]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), conf, cat, label)
    for (p, conf, cat, label) in _RAW_PATTERNS
]


# ── Result types ────────────────────────────────────────────────────────


@dataclass
class PatternMatch:
    confidence: Confidence
    category: str
    label: str
    matched_text: str
    location: str  # e.g. "arguments.query"

    def __str__(self) -> str:
        return (
            f"[{self.confidence.value.upper()}] "
            f"{self.category} @ {self.location}: "
            f"{self.label} — \"{self.matched_text[:60]}\""
        )


@dataclass
class InjectionResult:
    matches: list[PatternMatch] = field(default_factory=list)

    @property
    def has_high(self) -> bool:
        return any(m.confidence == Confidence.HIGH for m in self.matches)

    @property
    def high_count(self) -> int:
        return sum(1 for m in self.matches if m.confidence == Confidence.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for m in self.matches if m.confidence == Confidence.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for m in self.matches if m.confidence == Confidence.LOW)

    def recommend(self) -> Action:
        """
        Decide what to do based on aggregate match severity.

        Rules:
          - any HIGH      → BLOCK
          - 2+ MEDIUM     → BLOCK
          - 1 MEDIUM      → WARN
          - LOW only      → WARN
          - no matches    → ALLOW
        """
        if self.has_high:
            return Action.BLOCK
        if self.medium_count >= 2:
            return Action.BLOCK
        if self.medium_count >= 1 or self.low_count >= 1:
            return Action.WARN
        return Action.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": [
                {
                    "confidence": m.confidence.value,
                    "category": m.category,
                    "label": m.label,
                    "matched_text": m.matched_text,
                    "location": m.location,
                }
                for m in self.matches
            ],
            "summary": {
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "recommendation": self.recommend().value,
            },
        }


# ── Detector ────────────────────────────────────────────────────────────


class InjectionDetector:
    """
    Walks a JSON-like structure (dict / list / str) and flags any string
    leaf that matches a known prompt-injection pattern.
    """

    def __init__(self, max_depth: int = 6, max_string_len: int = 50_000):
        self.max_depth = max_depth
        self.max_string_len = max_string_len

    def scan(self, payload: Any, root_path: str = "arguments") -> InjectionResult:
        """Recursively scan `payload`, returning all matches found."""
        result = InjectionResult()
        self._walk(payload, root_path, result, depth=0)
        return result

    def scan_string(self, text: str, location: str = "input") -> InjectionResult:
        """Convenience: scan a single string."""
        result = InjectionResult()
        self._check_string(text, location, result)
        return result

    # ── internals ──

    def _walk(self, node: Any, path: str, result: InjectionResult, depth: int) -> None:
        if depth > self.max_depth:
            return
        if isinstance(node, str):
            self._check_string(node, path, result)
        elif isinstance(node, dict):
            for k, v in node.items():
                self._walk(v, f"{path}.{k}", result, depth + 1)
        elif isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                self._walk(item, f"{path}[{i}]", result, depth + 1)
        # numbers / bool / None — nothing to check

    def _check_string(self, text: str, location: str, result: InjectionResult) -> None:
        if not text:
            return
        snippet = text if len(text) <= self.max_string_len else text[: self.max_string_len]
        for regex, confidence, category, label in _COMPILED:
            for m in regex.finditer(snippet):
                result.matches.append(PatternMatch(
                    confidence=confidence,
                    category=category,
                    label=label,
                    matched_text=m.group(0),
                    location=location,
                ))
