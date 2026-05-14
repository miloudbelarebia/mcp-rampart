<h1 align="center">🛡️ mcp-rampart</h1>

<p align="center">
  <strong>Security ramparts for FastAPI apps exposed as MCP servers.</strong><br/>
  <em>Pre-flight audit. Runtime prompt-injection guardrail. One package.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/mcp-rampart/"><img src="https://img.shields.io/pypi/v/mcp-rampart?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/miloudbelarebia/mcp-rampart/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/miloudbelarebia/mcp-rampart/stargazers"><img src="https://img.shields.io/github/stars/miloudbelarebia/mcp-rampart?style=social" alt="Stars"></a>
</p>

---

```python
from fastapi import FastAPI
from mcp_rampart import MCPRampart

app = FastAPI()
# ... your existing routes ...

rampart = MCPRampart(app)                       # 1. Speak MCP.
report = rampart.audit()                        # 2. Audit what you'd expose.
if report.has_blockers():
    report.print_text(); raise SystemExit(1)

rampart.enable_guardrails(policy="block")       # 3. Block prompt-injection at runtime.
```

> **TL;DR.** MCP security tooling is fragmenting into layers. mcp-rampart is the only library that lives **inside your MCP server** — auditing the routes you're about to expose and scanning the arguments of every `tools/call` request. Everything else (gateways, firewalls, config scanners) lives elsewhere on the wire.

---

## The 4 layers of MCP security

MCP went from "experiment" to **97M+ installs per month** in 2026. Security tooling caught up only recently, and most of it solves a different problem than the one you have. Here's the map:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — The LLM itself (Claude, GPT, Gemini)                  │
│  Worry: hallucination, jailbreaks at the model level             │
│  → out of scope for everyone — model provider's problem          │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼  (JSON-RPC over MCP transport)
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2 — The MCP CLIENT (Claude Desktop, Cursor, agents)       │
│  Worry: the LLM calls something risky or exfiltrates data        │
│  Tools: pipelock, mcp-firewall, SecretiveShell/MCP-Bridge        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼  (HTTP / SSE)
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3 — The GATEWAY / proxy in front of the MCP server        │
│  Worry: who's allowed to talk to this server, with what auth     │
│  Tools: apache/casbin-gateway, hyprmcp/mcp-gateway               │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4 — The MCP SERVER itself ← 🛡️ mcp-rampart                │
│  Worry: did I expose dangerous routes? is an injection hiding    │
│         inside the arguments of every tools/call?                │
│  Tools: mcp-rampart (this project)                               │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼  (which servers are even installed?)
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5 — The USER's MCP config (~/.mcp.json, etc.)             │
│  Worry: am I installing a malicious server on my machine         │
│  Tools: apisec-inc/mcp-audit, ModelContextProtocol-Security/     │
│         mcpserver-audit                                          │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Question it answers | Representative tool |
|--:|---|---|
| 1 | "Is the model itself safe?" | (model provider) |
| 2 | "Is my agent leaking / calling something risky?" | [pipelock](https://github.com/luckyPipewrench/pipelock) (583⭐) |
| 3 | "Who's allowed to talk to my server, with what auth?" | [casbin-gateway](https://github.com/apache/casbin-gateway) (559⭐), [hyprmcp/mcp-gateway](https://github.com/hyprmcp/mcp-gateway) (92⭐) |
| **4** | **"Did I just hand a language model access to my admin endpoints? Is an injection sneaking into the args of every call?"** | **mcp-rampart** |
| 5 | "Is this MCP server I'm installing actually safe?" | [apisec mcp-audit](https://github.com/apisec-inc/mcp-audit) (149⭐), [mcpserver-audit](https://github.com/ModelContextProtocol-Security/mcpserver-audit) (16⭐) |

**You probably need more than one layer.** mcp-rampart is the only library that operates at layer 4 — the layer that solves the *MCP-server author's* problem rather than the operator's or the user's.

---

## Why "framework-aware", not "MCP-generic"

You'll notice every tool at layers 2, 3, and 5 is **framework-agnostic** — they intercept the wire (HTTP, JSON-RPC, config files) and don't care what's behind. That works for them because they don't need to.

mcp-rampart **needs to** look behind. The pre-flight audit literally cannot exist as a proxy:

| What mcp-rampart can see | Why (it's installed *in* the app) |
|---|---|
| `@app.get("/api/admin/users/...")` decorators | reads `app.routes` directly |
| Pydantic response models declaring `email`, `phone`, `ssn` | introspects `route.response_model` |
| Missing docstrings on tool handlers | reads `route.endpoint.__doc__` |
| Untyped parameters that fall back to `str` | reads `inspect.signature(handler)` |
| Path patterns that look like `/auth/`, `/oauth/`, `/internal/` | pattern-matches `route.path` |

A proxy at layer 3 sees `POST /mcp {"method":"tools/call","name":"delete_user","args":{...}}`. It does **not** see `@app.delete("/api/admin/users/{user_id}")` three steps upstream. So it can't tell you "you're about to expose your admin to an LLM" — it can only tell you "someone just called delete_user".

The trade-off: mcp-rampart is currently **FastAPI-only**. We're paying that price on purpose for now, because deep introspection is what makes the audit valuable. Node.js and Flask/Django are next on the roadmap.

---

## Where mcp-rampart is uniquely positioned

Five concrete cells where mcp-rampart is the only ✅:

| | mcp-rampart | pipelock | casbin-gw | apisec mcp-audit | hyprmcp |
|---|:--:|:--:|:--:|:--:|:--:|
| Runs **inside your FastAPI app** (no extra process) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Audits the **routes _you_ are about to expose** (not someone else's) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Refuses to start the server on **CRITICAL** findings | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Prompt-injection** detection on every `tools/call` | ✅ | partial | ❌ | ❌ | ❌ |
| Three-policy model (`block` / `alert` / `log`) + pluggable callbacks | ✅ | ❌ | ❌ | ❌ | ❌ |

Different shape, different question, different price tag.

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

rampart = MCPRampart(app)                       # auto-discovers routes, mounts /mcp
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

`rampart.audit()` walks every exposed tool and runs **8 checks**. Each finding gets a severity tag, a suggestion, and a category code you can match in CI.

| Severity | Check | Triggers when… |
|---|---|---|
| 🔴 CRITICAL | `EXPOSED_AUTH` | route path matches `/auth/`, `/login`, `/token`, `/oauth`, … |
| 🔴 CRITICAL | `EXPOSED_ADMIN` | route path matches `/admin/`, `/internal/`, `/debug/`, … |
| 🟠 HIGH | `MISSING_DOCSTRING` | no description → LLM will guess and call the wrong tool |
| 🟠 HIGH | `SENSITIVE_PARAM_NAME` | parameter name contains `password`, `token`, `api_key`, … |
| 🟠 HIGH | `PII_IN_RESPONSE` | response schema declares fields like `email`, `phone`, `ssn`, … |
| 🟡 MEDIUM | `DESTRUCTIVE_METHOD` | `DELETE` / `PUT` / `PATCH` exposed without an explicit consent flow |
| 🔵 LOW | `UNTYPED_PARAMETER` | 3+ parameters falling back to `str` — LLMs may send malformed inputs |
| 🔵 LOW | `WILDCARD_RESPONSE` | `GET` route with no `response_model` declared — LLM can't anticipate the output shape |

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
    slack.post(f"⚠️ mcp-rampart blocked {decision.tool_name}: {decision.reason}")

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

**Headline**: the official Auth0 example **exposes `/oauth/authorize`, `/oauth/register`, and `/.well-known/oauth-authorization-server` to LLM clients**. mcp-rampart catches all three and refuses to start the server. Full breakdown in [`case-studies/01-fastapi-mcp-examples.md`](case-studies/01-fastapi-mcp-examples.md).

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
│   │            mcp-rampart (embedded)            │   │
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
- [x] **v0.4** — 56-test pytest suite, GitHub Actions CI (py 3.10/3.11/3.12 + ruff + build), SECURITY.md, +1 audit check (`WILDCARD_RESPONSE`), +11 injection patterns (27 total: 10 HIGH / 8 MEDIUM / 9 LOW), issue & PR templates, FUNDING
- [ ] **v0.5** — **Node.js / TypeScript port** (`mcp-rampart-js` for Hono / Express / Fastify). Half of new MCP servers in 2026 ship in JS.
- [ ] **v0.6** — Flask + Django adapters (the rest of the Python web ecosystem)
- [ ] **v0.7** — Custom audit & guardrail rules (decorators / config / plugins) + tunable confidence thresholds
- [ ] **v0.8** — Auth passthrough (OAuth2 / API keys / JWT), stdio transport
- [ ] **v1.0** — Smart tool grouping (collapse CRUD into fewer tools), policy-as-code, OpenAPI/Asyncapi spec ingestion

---

## FAQ

**Why not just be a generic MCP proxy that works with any framework?**
Because the audit needs to read your code — Pydantic models, decorators, type hints, docstrings. A proxy on the wire can't see those. See [Why framework-aware](#why-framework-aware-not-mcp-generic).

**Is this the same as pipelock / casbin-gateway / hyprmcp / apisec mcp-audit?**
No. They live at layers 2, 3, and 5. mcp-rampart lives at layer 4. See [The 4 layers of MCP security](#the-4-layers-of-mcp-security).

**Do I still need a gateway / firewall if I use mcp-rampart?**
Probably yes. mcp-rampart catches code-side issues and runtime injection. A gateway adds auth + rate-limiting + network policy. They're complementary.

**What happens if mcp-rampart blocks a legitimate call?**
The MCP client receives an `isError: true` response with the diagnostic in the response body. Switch to `policy="alert"` while you tune patterns. You can also bypass per-route with `rampart.exclude(...)`.

**Can I add my own rules?**
Custom rules land in v0.6. Until then, subclass `Auditor` or `InjectionDetector` and pass it via `custom_detector=`.

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
