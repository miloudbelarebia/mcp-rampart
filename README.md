<h1 align="center">🛡️ MCPSentry</h1>

<p align="center">
  <strong>The MCP bridge that audits your routes before exposing them to LLMs — and blocks prompt-injection at runtime.</strong><br/>
  <em>One line to expose. One line to verify. One line to guard.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/mcpsentry/"><img src="https://img.shields.io/pypi/v/mcpsentry?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/miloudbelarebia/mcpsentry/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/miloudbelarebia/mcpsentry/stargazers"><img src="https://img.shields.io/github/stars/miloudbelarebia/mcpsentry?style=social" alt="Stars"></a>
</p>

---

```python
from fastapi import FastAPI
from mcpsentry import MCPSentry

app = FastAPI()
# ... your existing routes ...

bridge = MCPSentry(app)                    # Your app now speaks MCP.

report = bridge.audit()                    # Pre-flight security audit.
if report.has_blockers():
    report.print_text()                    # 🔴 CRITICAL: /api/admin exposed, /api/auth/login exposed…
    raise SystemExit(1)

bridge.enable_guardrails(policy="block")   # Runtime prompt-injection blocking.
```

> **MCPSentry** = a one-line FastAPI → MCP bridge **plus** a pre-flight security auditor **plus** a runtime guardrail that scans every `tools/call` for prompt-injection. Because handing an LLM root access to your API by accident is no longer hypothetical.

---

## Why MCPSentry exists

A `FastAPI → MCP` bridge alone isn't enough. The hard problem isn't *exposing* routes — it's making sure you only expose the routes you **meant** to.

When LLMs become callers of your API, three things go wrong silently:

| Risk | What happens | MCPSentry catches it |
|---|---|---|
| **Admin endpoints exposed** | `/api/admin/users/delete` becomes an MCP tool the LLM can call | 🔴 CRITICAL — refuses to start by default |
| **PII leaks in responses** | `/api/users/me` returns `email`, `phone`, `ssn` — now in LLM context | 🟠 HIGH — flags PII-named fields |
| **Auth flows accessible to LLM** | `/api/auth/login` callable with arbitrary credentials | 🔴 CRITICAL — refuses to start |
| **Missing docstrings** | LLM guesses what each tool does → calls the wrong one | 🟠 HIGH — fail the audit |
| **Untyped params** | Path param is `str`, LLM sends `"; rm -rf /"` | 🔵 LOW — flag for explicit typing |
| **Destructive DELETE/PUT/PATCH** | LLM mutates data without confirmation | 🟡 MEDIUM — informational |

Other libraries give you a bridge. MCPSentry gives you a bridge **and a security checklist that fails the build if you got it wrong.**

---

## Quick Start

```bash
pip install mcpsentry
```

```python
from fastapi import FastAPI
from mcpsentry import MCPSentry

app = FastAPI(title="My App")

@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    """Get a user by their ID."""
    return {"id": user_id, "name": "Alice"}

bridge = MCPSentry(app)            # Auto-discovers routes, mounts /mcp
print(bridge.summary())

# Always audit before deploying
report = bridge.audit()
report.print_text()

if report.has_blockers():
    raise SystemExit(1)
```

Your app now exposes:
- `GET /mcp` — Server info and tool listing
- `POST /mcp` — MCP JSON-RPC endpoint (Streamable HTTP transport)

Any MCP client (Claude, ChatGPT, Gemini, Cursor, Codex) can connect.

---

## The audit, explained

`bridge.audit()` walks every exposed tool and runs 7 checks. Sample output:

```
🛡️  MCPSentry audit report
   13 tools from 13 routes
   🔴 2 critical · 🟠 4 high · 🟡 3 medium · 🔵 1 low

   🔴 [CRITICAL] POST   /api/auth/login  —  Authentication endpoint exposed to LLM clients
      ↳ Add '/api/auth/login' to exclude_paths
   🔴 [CRITICAL] DELETE /api/admin/users/{user_id}  —  Admin / internal endpoint exposed to LLM clients
      ↳ Exclude this route from MCP exposure
   🟠 [HIGH    ] GET    /api/users/me  —  Response may leak PII fields: email, phone, address
      ↳ Mask PII before returning, or restrict this route from MCP exposure
   🟠 [HIGH    ] POST   /api/internal/run  —  No docstring — an LLM will guess this tool's purpose
      ↳ Add a clear docstring or `summary=` to the route decorator
   🟡 [MEDIUM  ] DELETE /api/recipes/{recipe_id}  —  Destructive DELETE — an LLM call can mutate/delete data
      ↳ Document the consequences in the docstring; consider requiring confirmation
   🔵 [LOW     ] GET    /api/search  —  3 parameters fall back to 'string' — LLMs may send malformed inputs
      ↳ Annotate parameters with explicit types (int, bool, list[str], Pydantic models)
```

### Programmatic use

```python
report = bridge.audit()

# Counts
report.critical_count           # → 2
report.high_count               # → 4

# Structured access (CI/CD, dashboards, reporting)
import json
print(json.dumps(report.to_dict(), indent=2))

# Iterate
for finding in report.findings:
    if finding.severity == Severity.CRITICAL:
        send_to_security_team(finding)
```

### Use it in CI

```yaml
# .github/workflows/mcp-audit.yml
- run: python -c "from myapp import bridge; r = bridge.audit(); r.print_text(); exit(1 if r.has_blockers() else 0)"
```

---

## 🎯 Real-world findings — see [`case-studies/`](case-studies/)

We ran `bridge.audit()` against the official examples of [`tadata-org/fastapi_mcp`](https://github.com/tadata-org/fastapi_mcp) (the most popular FastAPI→MCP library, 11.9k ⭐).

| Example | 🔴 Crit | 🟠 High | 🟡 Med | 🔵 Low | Verdict |
|---|--:|--:|--:|--:|---|
| `01_basic_usage_example` | 0 | 0 | 2 | 0 | ✅ |
| `02_full_schema_description` | 0 | 0 | 2 | 0 | ✅ |
| `04_separate_server` | 0 | 0 | 2 | 0 | ✅ |
| `08_auth_token_passthrough` | 0 | 1 | 2 | 0 | ✅ |
| **`09_auth_example_auth0`** | **3** | **6** | **0** | **1** | **❌ BLOCK** |

**Headline**: the official Auth0 example **exposes `/oauth/authorize`, `/oauth/register`, and `/.well-known/oauth-authorization-server` to LLM clients**. MCPSentry catches all three and refuses to start the server. Full breakdown in [`case-studies/01-fastapi-mcp-examples.md`](case-studies/01-fastapi-mcp-examples.md).

---

## Advanced configuration

```python
bridge = MCPSentry(
    app,
    name="My Recipe Manager",
    description="Search recipes, plan meals",
    include_paths=["/api/*"],                          # Only expose API routes
    exclude_paths=["/api/admin/*", "/api/auth/*"],     # Hide sensitive endpoints
    max_tools=30,                                      # Limit context window usage
    mcp_endpoint="/mcp",
)

# Refine specific tools for better LLM understanding
bridge.tool("/api/recipes/search", description="Find recipes by name or ingredients")
bridge.exclude("/api/internal/*")
```

---

## Live demo: Mealie Recipe Manager

The [`examples/mealie_demo/`](examples/mealie_demo/) directory contains a working demo that simulates [Mealie](https://github.com/mealie-recipes/mealie) (11.5K ⭐), a popular self-hosted recipe manager built with FastAPI.

```bash
git clone https://github.com/miloudbelarebia/mcpsentry
cd mcpsentry
pip install -e .
python examples/mealie_demo/app.py
```

What you'll see:

1. **Auto-discovery** — 13 Mealie routes → 13 MCP tools
2. **Pre-flight audit** — runs before the server starts
3. **Server starts** at `http://localhost:9925/mcp` (only if audit passes)

Connect from Claude Desktop:

```json
{
  "mcpServers": {
    "mealie": { "url": "http://localhost:9925/mcp" }
  }
}
```

Then ask Claude: *"What's for dinner tonight?"* — it'll search your recipes, propose a meal plan, build a shopping list.

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│                  Your FastAPI app                    │
│                                                     │
│   @app.get("/api/recipes")     ← Existing routes    │
│   @app.post("/api/recipes")                         │
│   @app.delete("/api/admin/...")  ← BAD              │
│                                                     │
│   ┌─────────────────────────────────────────────┐   │
│   │            MCPSentry (embedded)              │   │
│   │                                             │   │
│   │  1. Introspect routes at startup            │   │
│   │  2. Extract Pydantic schemas + type hints   │   │
│   │  3. ⚡ Pre-flight security audit             │   │
│   │     ↳ refuse to start on CRITICAL findings  │   │
│   │  4. Generate MCP tool definitions           │   │
│   │  5. Serve MCP JSON-RPC on /mcp              │   │
│   └─────────────────────────────────────────────┘   │
│                                                     │
│   POST /mcp  ← LLM clients connect here             │
└─────────────────────────────────────────────────────┘
         │
         ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐
   │  Claude   │ │  ChatGPT  │ │  Gemini   │ │ Cursor  │
   └───────────┘ └───────────┘ └───────────┘ └─────────┘
```

---

## Comparison with other tools

| | **MCPSentry** | fastapi_mcp | FastMCP `from_fastapi()` | openapi-mcp-server |
|---|---|---|---|---|
| 1-line setup | ✅ | ✅ | ✅ | ❌ (CLI + config) |
| Embedded (no separate process) | ✅ | ✅ | ✅ | ❌ |
| Auto-discovers routes (no OpenAPI spec) | ✅ | ✅ | ✅ | ❌ |
| **Pre-flight security audit** | **✅** | ❌ | ❌ | ❌ |
| **Refuses to start on CRITICAL findings** | **✅** | ❌ | ❌ | ❌ |
| **Runtime prompt-injection detection** | **✅** | ❌ | ❌ | ❌ |
| **Block / alert / log policy on tools/call** | **✅** | ❌ | ❌ | ❌ |
| Multi-framework (FastAPI + Flask + Django) | 🚧 v0.4 | ❌ | partial (OpenAPI) | spec-based |

If you don't care about auditing what you expose or what comes back through it, `fastapi_mcp` and `FastMCP` are fine. If you do, **MCPSentry is the only one that fails your build when you got it wrong — and your runtime when something looks off.**

---

## Runtime guardrails (v0.3)

The audit happens once, at startup. **The guardrail runs on every single `tools/call` request** while the server is alive.

It scans the call's `arguments` (recursively, in dicts and lists) against a curated catalogue of prompt-injection patterns:

| Confidence | Examples of what gets caught |
|---|---|
| 🔴 HIGH | `ignore previous instructions`, `you are now …`, `developer/admin/jailbreak mode`, chat-template control tokens (`<\|im_start\|>`), `[[system]]` markers |
| 🟠 MEDIUM | `system prompt`, `act as …`, `pretend to be …`, "reveal your instructions", "repeat everything above" |
| 🔵 LOW | exfiltration verbs (`send your tokens to …`), `<script>` payloads, embedded `curl/wget https://…`, base64 obfuscation |

Aggregate decision:
- any HIGH match → **BLOCK**
- 2+ MEDIUM matches → **BLOCK**
- 1 MEDIUM or LOW → **WARN**
- nothing → **ALLOW**

### Enable in one line

```python
bridge = MCPSentry(app)
bridge.audit()                         # pre-flight
bridge.enable_guardrails(policy="block")   # runtime
```

### Three policies, your call

```python
bridge.enable_guardrails(policy="block")   # refuse the call (default)
bridge.enable_guardrails(policy="alert")   # let it through, log loudly + on_alert callback
bridge.enable_guardrails(policy="log")     # shadow mode — just observe
```

### Plug your alerting in

```python
def to_security_team(decision):
    slack.post(f"⚠️ MCPSentry blocked {decision.tool_name}: {decision.reason}")

bridge.enable_guardrails(policy="block", on_block=to_security_team)
```

### Inspect what happened

```python
bridge.guardrail.stats()
# → {"total": 1284, "blocked": 7, "alerted": 23, "clean": 1254}

for entry in bridge.guardrail.recent(10):
    print(entry.tool_name, entry.decision.allowed, entry.decision.reason)
```

What an MCP client sees when blocked:

```json
{
  "isError": true,
  "content": [{
    "type": "text",
    "text": "🛡️ Blocked by MCPSentry runtime guardrail.\nReason: Prompt-injection detected (HIGH:1 MEDIUM:0 LOW:0)\nTop matches: high instruction_override @ arguments.query"
  }]
}
```

---

## Roadmap

- [x] **v0.1** — FastAPI introspection, MCP Streamable HTTP transport, examples
- [x] **v0.2** — `bridge.audit()` with 7 security checks, severity levels, JSON/text output
- [x] **v0.3** — Runtime guardrails: prompt-injection detection + block/alert/log policy + structured callbacks
- [ ] **v0.4** — Multi-framework: Flask + Django adapters (the real white space)
- [ ] **v0.5** — Custom audit & guardrail rules (decorators / config / plugins)
- [ ] **v0.6** — OAuth2 / API key auth passthrough, stdio transport
- [ ] **v1.0** — Smart tool grouping (collapse CRUD into fewer tools), policy-as-code

---

## Contributing

```bash
git clone https://github.com/miloudbelarebia/mcpsentry
cd mcpsentry
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/miloudbelarebia">Miloud Belarebia</a><br/>
  <em>Securing the agentic web, one audit at a time.</em>
</p>
