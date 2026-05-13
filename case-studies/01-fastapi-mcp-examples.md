# Case Study: `tadata-org/fastapi_mcp` Examples

**Project**: [tadata-org/fastapi_mcp](https://github.com/tadata-org/fastapi_mcp) — 11.9k ⭐, MIT
**Why interesting**: The dominant FastAPI-to-MCP library on the market. If their official examples ship with security issues, MCPRampart's value proposition is no longer hypothetical.
**Audited at commit**: HEAD (May 2026)

---

## 1. `examples/shared/apps/items.py` (basic CRUD)

```
🛡️  MCPRampart audit report
   6 tools from 6 routes
   🔴 0 critical · 🟠 0 high · 🟡 2 medium · 🔵 0 low

   🟡 [MEDIUM] PUT    /items/{item_id}  —  Destructive PUT — an LLM call can mutate/delete data
   🟡 [MEDIUM] DELETE /items/{item_id}  —  Destructive DELETE — an LLM call can mutate/delete data

Verdict: ✅ PASS
```

**Comment**: Clean. The two MEDIUM findings are informational reminders about destructive verbs; routes are docstring-ed and use Pydantic types correctly.

---

## 2. `examples/02_full_schema_description_example.py`

```
Routes: 6 | Tools: 6 | Findings: 🔴0 🟠0 🟡2 🔵0
  🟡 [MEDIUM] PUT    /items/{item_id}  —  Destructive PUT
  🟡 [MEDIUM] DELETE /items/{item_id}  —  Destructive DELETE

Verdict: ✅ PASS
```

**Comment**: Same shape as items.py — they're using the same backing app.

---

## 3. `examples/04_separate_server_example.py`

```
Routes: 6 | Tools: 6 | Findings: 🔴0 🟠0 🟡2 🔵0

Verdict: ✅ PASS
```

**Comment**: Identical signature. Demonstrates the architectural difference (separate server) but exposes the same surface.

---

## 4. `examples/08_auth_example_token_passthrough.py`

```
Routes: 7 | Tools: 7 | Findings: 🔴0 🟠1 🟡2 🔵0

  🟠 [HIGH]   GET    /private  —  No docstring — an LLM will guess this tool's purpose
  🟡 [MEDIUM] PUT    /items/{item_id}  —  Destructive PUT
  🟡 [MEDIUM] DELETE /items/{item_id}  —  Destructive DELETE

Verdict: ✅ PASS
```

**Comment**: Adds a `/private` route as part of the auth demo. Missing docstring means an LLM has no information about what `/private` does — it'll either ignore the tool or call it blindly. MCPRampart flags this as HIGH because it directly degrades LLM tool selection.

---

## 5. `examples/09_auth_example_auth0.py` 🎯

```
Routes: 5 | Tools: 5 | Findings: 🔴3 🟠6 🟡0 🔵1

  🔴 [CRITICAL] GET  /.well-known/oauth-authorization-server  —  Authentication endpoint exposed to LLM clients
       ↳ Add '/.well-known/oauth-authorization-server' to exclude_paths
  🔴 [CRITICAL] GET  /oauth/authorize  —  Authentication endpoint exposed to LLM clients
       ↳ Add '/oauth/authorize' to exclude_paths
  🔴 [CRITICAL] POST /oauth/register  —  Authentication endpoint exposed to LLM clients
       ↳ Add '/oauth/register' to exclude_paths
  🟠 [HIGH]     GET  /api/public           —  No docstring — an LLM will guess this tool's purpose
  🟠 [HIGH]     GET  /api/protected        —  No docstring — an LLM will guess this tool's purpose
  (4 more HIGH findings for other missing-docstring routes)
  🔵 [LOW]      …

Verdict: ❌ BLOCK
```

### What this means

The Auth0 example, when used as a template, exposes the **entire OAuth2 dance** to any connected MCP client. An LLM agent given the server's URL could:
- Call `/oauth/register` to register itself as a client
- Call `/oauth/authorize` to initiate an authorization flow
- Read `/.well-known/oauth-authorization-server` to learn the server's auth metadata

None of this is necessarily exploitable on its own — but **none of it should be visible to an LLM agent that's supposed to call your application APIs**. These routes exist for OAuth clients, not for tool-calling.

MCPRampart's default behaviour:
```python
report = bridge.audit()
if report.has_blockers():
    report.print_text()
    raise SystemExit(1)   # ← server refuses to start
```

The developer is forced to either:
1. Explicitly exclude the OAuth routes (`exclude_paths=['/oauth/*', '/.well-known/*']`)
2. Acknowledge the finding and override the blocker (which leaves an audit trail)

Neither of these happens automatically with `fastapi_mcp`. There is no built-in audit step.

---

## Comparison

| | `fastapi_mcp` alone | `fastapi_mcp` + manual review | `mcp_rampart` |
|---|---|---|---|
| Detects auth endpoints | ❌ | depends on reviewer | ✅ |
| Detects PII fields | ❌ | depends on reviewer | ✅ |
| Detects untyped params | ❌ | depends on reviewer | ✅ |
| Detects missing docstrings | ❌ | depends on reviewer | ✅ |
| Fails CI on critical | ❌ | manual | ✅ `has_blockers()` |
| Time to write | 0 | hours per project | 1 line: `bridge.audit()` |
