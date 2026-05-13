<h1 align="center">🛡️ MCPRampart</h1>

<p align="center">
  <strong>Security for the FastAPI apps you expose to LLMs via MCP.</strong><br/>
  <em>Pre-flight audit. Runtime prompt-injection guardrail. One package.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/mcp_rampart/"><img src="https://img.shields.io/pypi/v/mcp-rampart?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/miloudbelarebia/mcp-rampart/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/miloudbelarebia/mcp-rampart/stargazers"><img src="https://img.shields.io/github/stars/miloudbelarebia/mcp-rampart?style=social" alt="Stars"></a>
</p>

---

```python
from fastapi import FastAPI
from mcp_rampart import MCPRampart

app = FastAPI()
# ... your existing routes ...

rampart = MCPRampart(app)                    # 1. Speak MCP.
report = rampart.audit()                    # 2. Audit what you'd expose.
if report.has_blockers():
    report.print_text(); raise SystemExit(1)

rampart.enable_guardrails(policy="block")   # 3. Block prompt-injection at runtime.
```

---

## Why this exists

MCP has gone from "interesting experiment" to **97M+ installs per month** in 2026. Anthropic, OpenAI, Google, Cursor, Codex, Microsoft — every major agent ships MCP support, and the Linux Foundation now stewards the protocol. The dev tooling around it has scaled fast.

**The security tooling around it has not.**

Every FastAPI app shipped as an MCP server is one careless `include_paths=["/*"]` away from handing a language model:
- its admin endpoints,
- its auth/OAuth flows,
- the columns of its user table,
- the verbs that mutate data.

And once it's live, **every single `tools/call` request is untrusted input** — written by a model that may have been told to "ignore previous instructions" two turns ago.

MCPRampart is two things in one package, designed to make those two failure modes hard to ignore:

1. **A pre-flight `audit()`** that walks every route you'd expose and refuses to start the server when something looks dangerous.
2. **A runtime `Guardrail`** that scans the arguments of every `tools/call` against a curated prompt-injection pattern catalogue and blocks the call before your handler runs.

You don't have to integrate three libraries, write your own regex layer, or stand up a separate proxy. It's `pip install mcp-rampart` and three lines of code.

---

## Quick start

```bash
pip install mcp-rampart
```

```python
from fastapi import FastAPI
from mcp_rampart import MCPRampart

app = FastAPI(title="My App")

@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    """Get a user by their ID."""
    return {"id": user_id, "name": "Alice"}

rampart = MCPRampart(app)                    # auto-discovers routes, mounts /mcp
print(rampart.summary())

# Pre-flight audit — refuses to start the server on CRITICAL findings
report = rampart.audit()
report.print_text()
if report.has_blockers():
    raise SystemExit(1)

# Runtime guardrail — every incoming tools/call is scanned
rampart.enable_guardrails(policy="block")
```

Your app now exposes:
- `GET /mcp` — server info and tool listing
- `POST /mcp` — MCP JSON-RPC endpoint (Streamable HTTP transport)

Any MCP client (Claude Desktop, ChatGPT, Gemini, Cursor, Codex) can connect.

---

## The pre-flight audit, in detail

`rampart.audit()` walks every exposed tool and runs **7 checks**. Each finding gets a severity tag, a suggestion, and a category code you can match in CI.

| Severity | Check | Triggers when… |
|---|---|---|
| 🔴 CRITICAL | `EXPOSED_AUTH` | route path matches `/auth/`, `/login`, `/token`, `/oauth`, … |
| 🔴 CRITICAL | `EXPOSED_ADMIN` | route path matches `/admin/`, `/internal/`, `/debug/`, … |
| 🟠 HIGH | `MISSING_DOCSTRING` | no description → LLM will guess and call the wrong tool |
| 🟠 HIGH | `SENSITIVE_PARAM_NAME` | parameter name contains `password`, `token`, `api_key`, … |
| 🟠 HIGH | `PII_IN_RESPONSE` | response schema declares fields like `email`, `phone`, `ssn`, … |
| 🟡 MEDIUM | `DESTRUCTIVE_METHOD` | `DELETE` / `PUT` / `PATCH` exposed without explicit consent flow |
| 🔵 LOW | `UNTYPED_PARAMETER` | 3+ parameters falling back to `str` — LLMs may send malformed inputs |

Sample output on a deliberately bad app:

```
🛡️  MCPRampart audit report
   13 tools from 13 routes
   🔴 2 critical · 🟠 4 high · 🟡 3 medium · 🔵 1 low

   🔴 [CRITICAL] POST   /api/auth/login           Authentication endpoint exposed to LLM clients
      ↳ Add '/api/auth/login' to exclude_paths
   🔴 [CRITICAL] DELETE /api/admin/users/{user_id}  Admin / internal endpoint exposed to LLM clients
      ↳ Exclude this route from MCP exposure
   🟠 [HIGH]     GET    /api/users/me              Response may leak PII fields: email, phone, address
   …
```

Use it in CI:

```yaml
- run: python -c "from myapp import rampart; r = rampart.audit(); r.print_text(); exit(1 if r.has_blockers() else 0)"
```

---

## The runtime guardrail, in detail

The audit happens once, at startup. **The guardrail runs forever — on every `tools/call` request.**

It scans the call's `arguments` (recursively, in dicts and lists) against a curated catalogue of prompt-injection patterns:

| Confidence | What gets caught |
|---|---|
| 🔴 HIGH | `ignore previous instructions`, `you are now …`, `developer/admin/jailbreak mode`, chat-template control tokens (`<\|im_start\|>`), `[[system]]` markers, `SYSTEM: do …` |
| 🟠 MEDIUM | `system prompt`, `act as …`, `pretend to be …`, "reveal your instructions", "repeat everything above", "begin new session as" |
| 🔵 LOW | exfiltration verbs (`send your tokens to …`), `<script>` payloads, embedded `curl/wget https://…`, base64 obfuscation |

Aggregate decision:
- any HIGH match → **BLOCK**
- 2+ MEDIUM matches → **BLOCK**
- 1 MEDIUM or LOW → **WARN** (allowed, logged)
- nothing → **ALLOW**

### Enable in one line

```python
rampart.enable_guardrails(policy="block")     # default
rampart.enable_guardrails(policy="alert")     # let through, log loudly, call on_alert
rampart.enable_guardrails(policy="log")       # observability / shadow mode
```

### Plug your alerting in

```python
def to_security_team(decision):
    slack.post(f"⚠️ MCPRampart blocked {decision.tool_name}: {decision.reason}")

rampart.enable_guardrails(policy="block", on_block=to_security_team)
```

### Inspect what happened

```python
rampart.guardrail.stats()
# → {"total": 1284, "blocked": 7, "alerted": 23, "clean": 1254}

for entry in rampart.guardrail.recent(10):
    print(entry.tool_name, entry.decision.allowed, entry.decision.reason)
```

What an MCP client sees when blocked:

```json
{
  "isError": true,
  "content": [{
    "type": "text",
    "text": "🛡️ Blocked by MCPRampart runtime guardrail.\nReason: Prompt-injection detected (HIGH:1)\nTop matches: high instruction_override @ arguments.query"
  }]
}
```

---

## 🎯 Real-world findings — see [`case-studies/`](case-studies/)

We ran `rampart.audit()` against the official examples of [`tadata-org/fastapi_mcp`](https://github.com/tadata-org/fastapi_mcp) (the most popular FastAPI→MCP library, 11.9k ⭐):

| Example | 🔴 Crit | 🟠 High | 🟡 Med | 🔵 Low | Verdict |
|---|--:|--:|--:|--:|---|
| `01_basic_usage_example` | 0 | 0 | 2 | 0 | ✅ |
| `02_full_schema_description` | 0 | 0 | 2 | 0 | ✅ |
| `04_separate_server` | 0 | 0 | 2 | 0 | ✅ |
| `08_auth_token_passthrough` | 0 | 1 | 2 | 0 | ✅ |
| **`09_auth_example_auth0`** | **3** | **6** | **0** | **1** | **❌ BLOCK** |

**Headline**: the official Auth0 example **exposes `/oauth/authorize`, `/oauth/register`, and `/.well-known/oauth-authorization-server` to LLM clients**. MCPRampart catches all three and refuses to start the server. Full breakdown in [`case-studies/01-fastapi-mcp-examples.md`](case-studies/01-fastapi-mcp-examples.md).

---

## Where MCPRampart sits in the MCP-security landscape

MCP security tools have started shipping. Here's an honest map:

| Project | ⭐ | Shape | What it does |
|---|--:|---|---|
| **`mcp_rampart` (this)** | new | **Embedded library** (`pip install` into your FastAPI app) | **Pre-flight audit of your own routes + runtime injection guardrail on every `tools/call`** |
| [`luckyPipewrench/pipelock`](https://github.com/luckyPipewrench/pipelock) | 583 | Client-side firewall | Agent egress control, DLP, sits between agent and MCP server |
| [`apache/casbin-gateway`](https://github.com/apache/casbin-gateway) | 559 | HTTP gateway | Casbin policy enforcement in front of MCP traffic |
| [`apisec-inc/mcp-audit`](https://github.com/apisec-inc/mcp-audit) | 149 | Config scanner | Scans `mcp.json` for exposed secrets / unsafe servers installed on your machine |
| [`hyprmcp/mcp-gateway`](https://github.com/hyprmcp/mcp-gateway) | 92 | OAuth proxy | DCR + analytics in front of MCP servers |
| [`ModelContextProtocol-Security/mcpserver-audit`](https://github.com/ModelContextProtocol-Security/mcpserver-audit) | 16 | CLI | Audit MCP servers *before* you install them |

**Where MCPRampart is the only one ✅**

| | mcp_rampart | pipelock | casbin-gateway | apisec mcp-audit | hyprmcp |
|---|:--:|:--:|:--:|:--:|:--:|
| Runs **inside your FastAPI app** (no extra process) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Audits the **routes _you_ are about to expose** (not someone else's) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Refuses to start the server on **CRITICAL** findings | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Prompt-injection** detection on every `tools/call` | ✅ | partial | ❌ | ❌ | ❌ |
| Pluggable `on_block` / `on_alert` callbacks | ✅ | ❌ | ❌ | ❌ | ❌ |
| Three-policy model (`block` / `alert` / `log`) | ✅ | ❌ | ❌ | ❌ | ❌ |

The gateway / firewall / config-scanner projects each solve a real problem **for the agent operator or the MCP user**. MCPRampart solves the dual problem **for the MCP server author**: did you accidentally expose something dangerous, and if so, are you willing to ship anyway?

If you're building an MCP server (not consuming someone else's), this is the layer you don't currently have.

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
│   │            MCPRampart (embedded)              │   │
│   │                                             │   │
│   │  1. Introspect routes at startup            │   │
│   │  2. Extract Pydantic schemas + type hints   │   │
│   │  3. ⚡ Pre-flight security audit             │   │
│   │     ↳ refuse to start on CRITICAL findings  │   │
│   │  4. Generate MCP tool definitions           │   │
│   │  5. Mount JSON-RPC at /mcp                  │   │
│   │  6. 🛡️  Scan every tools/call for injection │   │
│   │     ↳ block / alert / log per policy        │   │
│   └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
         │
         ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐
   │  Claude   │ │  ChatGPT  │ │  Gemini   │ │ Cursor  │
   └───────────┘ └───────────┘ └───────────┘ └─────────┘
```

---

## Roadmap

- [x] **v0.1** — FastAPI introspection, MCP Streamable HTTP transport, examples
- [x] **v0.2** — `rampart.audit()` with 7 security checks, severity levels, JSON/text output
- [x] **v0.3** — Runtime guardrails: prompt-injection detection + block/alert/log policy + structured callbacks
- [ ] **v0.4** — Multi-framework: Flask + Django adapters (the real white space)
- [ ] **v0.5** — Custom audit & guardrail rules (decorators / config / plugins) + tunable confidence thresholds
- [ ] **v0.6** — Auth passthrough (OAuth2 / API keys / JWT), stdio transport
- [ ] **v1.0** — Smart tool grouping (collapse CRUD into fewer tools), policy-as-code, OpenAPI/Asyncapi spec ingestion

---

## Contributing

```bash
git clone https://github.com/miloudbelarebia/mcp-rampart
cd mcp-rampart
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
  <em>97M MCP installs per month. Someone has to audit what they expose.</em>
</p>
