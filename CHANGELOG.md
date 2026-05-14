# Changelog

All notable changes to **mcp-rampart** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/) and we use
[Semantic Versioning](https://semver.org/).

## [0.4.0] — 2026-05-14

### Added
- **Test suite** under `tests/` covering the four modules (core,
  audit, injection, runtime) — 40+ test cases. Run with `pytest -q`.
- **GitHub Actions CI** (`.github/workflows/ci.yml`) running pytest on
  Python 3.10/3.11/3.12, ruff check + format, and a build/twine-check job
  on every push and PR.
- **SECURITY.md** with a private disclosure address and supported-version
  policy.
- **Issue & PR templates** under `.github/ISSUE_TEMPLATE/` and
  `.github/PULL_REQUEST_TEMPLATE.md`.
- **`.github/FUNDING.yml`** wiring the GitHub Sponsors button.
- New injection categories: `markdown_injection`, `code_execution`,
  `path_traversal`, `notebook_escape`, `legacy_jailbreak`,
  `indirect_via_quote` — covering ~6 well-known patterns the v0.3
  detector missed.
- New audit category: `WILDCARD_RESPONSE` — flags routes that don't
  declare `response_model`, so the LLM gets unpredictable output shapes.

### Changed
- Re-grouped the injection pattern catalogue by category to make the
  source easier to read & extend.

### Fixed
- Minor: ensured all public `*.to_dict()` methods round-trip cleanly
  through `json.dumps` (tested).

## [0.3.4] — 2026-05-13

### Changed
- Rewrote README around the **4 layers of MCP security** taxonomy, a
  framework-aware vs MCP-generic explanation, comparison matrix, and
  a 5-question FAQ.
- Roadmap reshuffled: **Node.js / TypeScript** port becomes v0.4
  target ahead of Flask/Django (now v0.5), since most new MCP servers
  in 2026 ship in JS.
- Title rendered as `mcp-rampart` (matching `pip install`) instead of
  `MCPRampart`.

## [0.3.3] — 2026-05-13

### Changed
- Scrubbed every remaining mention of "bridge" from the public surface.
  Internal module renamed `mcp_rampart/bridge.py` → `mcp_rampart/core.py`
  (`MCPRampart` still importable from `mcp_rampart` top-level).
- pyproject description, module docstrings, CONTRIBUTING, examples and
  case-studies reworded to the security-toolkit framing.

## [0.3.2] — 2026-05-13

### Changed
- User-facing example variable renamed from `bridge` to `rampart`
  across README, docstrings, examples and case-studies. Internal closure
  `bridge = self` also renamed for consistency.

## [0.3.1] — 2026-05-13

### Changed
- Renamed package from `mcpsentry` to `mcp-rampart` (PyPI rejected
  `mcpsentry` as too similar to the unrelated `mcp-sentry` package).
- Top-level class `MCPSentry` → `MCPRampart`.

## [0.3.0] — 2026-05-12 _(unreleased on PyPI under this name — see 0.3.1)_

### Added
- **Runtime Guardrails** (`mcp_rampart.runtime`): a `Guardrail` class
  that intercepts every `tools/call` and runs the arguments through
  an `InjectionDetector`. Three policies (`block` / `alert` / `log`),
  pluggable `on_block` / `on_alert` callbacks, bounded in-memory
  history and aggregate `.stats()`.
- **Prompt-injection detector** (`mcp_rampart.injection`): 16 regex
  patterns across 14 categories at three confidence levels
  (HIGH/MEDIUM/LOW). Walks dicts/lists recursively up to a configurable
  depth.
- `rampart.enable_guardrails(policy=...)` one-liner to wire it up.

### Fixed
- `POST /mcp` returned HTTP 422 under `from __future__ import
  annotations` because FastAPI couldn't resolve the `Request` type at
  decoration time. Switched the handler to `payload: dict = Body(...)`.

## [0.2.0] — 2026-05-12

### Added
- **Pre-flight `audit()`** with seven checks: `EXPOSED_AUTH`,
  `EXPOSED_ADMIN`, `MISSING_DOCSTRING`, `SENSITIVE_PARAM_NAME`,
  `PII_IN_RESPONSE`, `DESTRUCTIVE_METHOD`, `UNTYPED_PARAMETER`.
  Each finding carries severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), a
  suggestion and a category code.
- `AuditReport` with `has_blockers()`, `format_text()`,
  `print_text()`, `to_dict()`.
- `case-studies/` with real audit findings on the official examples
  of `tadata-org/fastapi_mcp` (11.9k⭐) — including the Auth0 example
  that exposes 3 OAuth endpoints to LLM clients.

## [0.1.0] — initial

- FastAPI route introspection.
- MCP Streamable HTTP transport at `POST /mcp`.
- Mealie-like demo app under `examples/`.
