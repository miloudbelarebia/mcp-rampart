# mcp-rampart — Launch kit

Everything you need to copy-paste to launch and communicate about
mcp-rampart on day 1. Edit, swap voices, drop the parts you don't
like.

---

## TL;DR for yourself

| Length | One-line elevator |
|---|---|
| 8 words | **"Audit + injection guard for FastAPI MCP servers."** |
| 18 words | **"mcp-rampart is the only library that sits *inside* your FastAPI MCP server and refuses to ship dangerous routes."** |
| 1 paragraph | MCP installs crossed 97M/month in 2026. Five tools shipped in the last year to secure MCP — all of them sit on the wire (gateways, firewalls, config scanners). None of them looks *inside* the server at the routes you're about to hand to a language model. **mcp-rampart does**: it audits your FastAPI routes at startup (admin endpoints exposed? PII fields in responses? missing docstrings?), refuses to start on CRITICAL findings, and scans every `tools/call` request at runtime for prompt-injection patterns. `pip install mcp-rampart`, three lines of code. |

---

## The 30-second pitch (for video / Reel / meetings)

> *"MCP — Anthropic's protocol — passed 97 million installs per month in 2026. Every major AI agent uses it. But nobody's auditing what those servers expose.*
>
> *I shipped `mcp-rampart` last week. It's the only library that sits **inside** your FastAPI MCP server, audits the routes you're about to expose to a language model, and refuses to start if you forgot to exclude your admin or auth endpoints. Then at runtime it scans every tool call for prompt-injection patterns and blocks the dangerous ones.*
>
> *I tested it against the official examples of `fastapi_mcp` — the most popular FastAPI-to-MCP library, 12k stars. Their Auth0 example exposes three OAuth endpoints to LLM clients. `mcp-rampart` catches all three and refuses to boot.*
>
> *Install: `pip install mcp-rampart`. Three lines of code. MIT."*

---

## The 2-minute pitch (for podcast / longer demo)

Add to the 30-second version:

> *"Why FastAPI-only for now? Because the audit needs to read your code — Pydantic response models, `@app.delete` decorators, type hints, docstrings. A proxy on the wire can't see those. It can only see 'POST /mcp tools/call with these JSON args'. It doesn't see that the args ultimately hit `@app.delete("/api/admin/users/{user_id}")` three steps upstream.*
>
> *That's why mcp-rampart is **embedded**, not a proxy. Node.js port comes in v0.5 — that's where most new MCP servers ship in 2026.*
>
> *Eight audit checks: auth, admin, missing docstring, sensitive param, PII in response, destructive verb, untyped fallback, wildcard response. Twenty-seven injection patterns across three confidence levels.*
>
> *Three runtime policies: block, alert, log. Three lines to wire it in. Refuses to start on CRITICAL findings — your CI fails before the bug ships, not after."*

---

## LinkedIn post (English)

```
🛡️ I shipped mcp-rampart on PyPI.

It's the security layer for FastAPI apps you expose as MCP servers.

Quick context:
MCP — Anthropic's Model Context Protocol — passed 97M installs/month in 2026. Every major agent ships MCP support: Claude, ChatGPT, Gemini, Cursor, Codex. And we're starting to ship MCP servers in production.

But here's the thing: most security tooling for MCP solves the *operator's* problem (gateways, firewalls, config scanners). Almost nothing solves the *server author's* problem:

→ Did I accidentally expose my /admin route to a language model?
→ Is my /api/users response leaking email + phone + ssn into the LLM's context?
→ Is the LLM sending "ignore previous instructions" as one of my tool's arguments?

mcp-rampart answers those, in three lines:

  rampart = MCPRampart(app)
  rampart.audit().print_text()                  # 8 security checks pre-deploy
  rampart.enable_guardrails(policy="block")     # 27 injection patterns at runtime

I tested it against the official Auth0 example of fastapi_mcp (12k⭐ — the most popular library in the space). The example exposes /oauth/authorize, /oauth/register, and the OAuth metadata endpoint to LLM clients. mcp-rampart catches all three and refuses to start the server.

If you ship MCP, please audit before you boot.

→ https://github.com/miloudbelarebia/mcp-rampart
→ pip install mcp-rampart

#MCP #AISecurity #FastAPI #LLM #PromptInjection #OpenSource
```

## LinkedIn post (Français)

```
🛡️ J'ai publié mcp-rampart sur PyPI.

C'est une couche de sécurité pour les apps FastAPI exposées comme MCP servers.

Contexte rapide :
MCP — le Model Context Protocol d'Anthropic — a dépassé 97M installs/mois en 2026. Tous les agents majeurs le shippent : Claude, ChatGPT, Gemini, Cursor, Codex. On commence à mettre des MCP servers en prod.

Sauf que la plupart des outils de sécurité MCP résolvent le problème de *l'opérateur* (gateways, firewalls, scanners de config). Quasi rien ne résout le problème de *l'auteur du serveur* :

→ Est-ce que j'ai accidentellement exposé ma route /admin à un LLM ?
→ Est-ce que mon /api/users renvoie email + téléphone + ssn dans le contexte du LLM ?
→ Est-ce que le LLM envoie "ignore previous instructions" dans les args de mon tool ?

mcp-rampart répond à tout ça, en 3 lignes :

  rampart = MCPRampart(app)
  rampart.audit().print_text()                  # 8 checks de sécu pre-deploy
  rampart.enable_guardrails(policy="block")     # 27 patterns d'injection au runtime

Je l'ai testé sur l'exemple Auth0 officiel de fastapi_mcp (12k⭐ — la lib la plus populaire). Leur exemple expose /oauth/authorize, /oauth/register et le metadata OAuth aux clients LLM. mcp-rampart catch les 3 et refuse de démarrer le serveur.

Si tu ship MCP, audit avant boot.

→ https://github.com/miloudbelarebia/mcp-rampart
→ pip install mcp-rampart

#MCP #AISecurity #FastAPI #LLM #PromptInjection #OpenSource
```

---

## X / Twitter — 3-tweet thread

**Tweet 1 (hook)** :
```
🛡️ shipped mcp-rampart on PyPI.

97M MCP installs/month in 2026.
zero libraries audit what those servers expose to LLMs.
mcp-rampart is the only one that does.

audit + runtime injection guard. 3 lines.

→ pip install mcp-rampart
github.com/miloudbelarebia/mcp-rampart
```

**Tweet 2 (proof)** :
```
proof it matters:

I audited the official Auth0 example of fastapi_mcp (12k⭐, the most popular FastAPI→MCP lib).

it exposes /oauth/authorize, /oauth/register, and OAuth metadata to LLM clients.

mcp-rampart catches all 3. refuses to start the server.

[screenshot of the BLOCK output]
```

**Tweet 3 (close)** :
```
how it works:
- 8 pre-flight checks (admin/auth exposure, PII in responses, missing docstrings, destructive verbs…)
- 27 prompt-injection patterns scanned per tools/call
- 3 policies: block / alert / log
- FastAPI today, Node.js / Hono / Express coming v0.5

MIT. one pip install. 3 lines.
```

---

## Hacker News — Show HN format

```
Title: Show HN: mcp-rampart – pre-flight audit + runtime injection guard for FastAPI MCP servers

Body:

Hi HN,

I built mcp-rampart because the MCP security tooling landscape solves the
operator's problem (gateways, firewalls, config scanners), not the server
author's. If you ship a FastAPI app as an MCP server, there's no library
that:

  1. tells you, at startup, that you accidentally exposed your /admin
     routes to a language model;
  2. refuses to boot when something looks dangerous;
  3. scans every tools/call request at runtime for prompt-injection
     patterns and blocks the bad ones.

mcp-rampart does the three, with `pip install mcp-rampart` and three
lines of code:

    rampart = MCPRampart(app)
    rampart.audit().print_text()
    rampart.enable_guardrails(policy="block")

Eight audit checks (auth/admin exposure, PII in responses, missing
docstrings, sensitive params, destructive verbs, untyped fallbacks,
wildcard responses), 27 injection patterns at three confidence levels.

I tested it against the official Auth0 example of fastapi_mcp (the
most popular FastAPI→MCP library, ~12k stars). Their example exposes
/oauth/authorize, /oauth/register, and the OAuth metadata endpoint to
LLM clients. mcp-rampart catches all three and refuses to start.

Why FastAPI-only for now? The audit needs to read your code — Pydantic
models, decorators, type hints, docstrings. A wire-level proxy can't.
Node.js (Hono / Express / Fastify) is the next port. Flask + Django
after.

MIT, no telemetry, no SaaS upsell. 56-test pytest suite, CI on every
PR.

GitHub: https://github.com/miloudbelarebia/mcp-rampart
PyPI: https://pypi.org/project/mcp-rampart/

Feedback and pattern submissions welcome. There's a dedicated issue
template ("missing injection pattern / audit check") if you find one
that should have been flagged.
```

---

## Reddit r/Python

```
Title: I built mcp-rampart — a security layer for FastAPI apps exposed as MCP servers (pre-flight audit + runtime prompt-injection guardrail)

Body:

Hey r/Python,

Quick share of a small library I just put on PyPI: **mcp-rampart**.

**What it does**

```python
from fastapi import FastAPI
from mcp_rampart import MCPRampart

app = FastAPI()
# ... your routes ...

rampart = MCPRampart(app)
report = rampart.audit()
if report.has_blockers():
    report.print_text()
    raise SystemExit(1)

rampart.enable_guardrails(policy="block")
```

Line by line:

- `MCPRampart(app)` turns your FastAPI app into an MCP server (mounts
  `/mcp`, auto-generates tool definitions from your routes).
- `rampart.audit()` walks every exposed tool and runs 8 checks:
  exposed auth/admin endpoints, PII fields in responses, missing
  docstrings, sensitive param names, destructive verbs, untyped
  fallbacks, etc. Refuses to start the server on CRITICAL findings.
- `rampart.enable_guardrails()` scans the `arguments` of every
  `tools/call` request against 27 prompt-injection patterns (across
  three confidence levels: HIGH / MEDIUM / LOW). Three policies:
  `block`, `alert`, `log`.

**Why I built it**

There's a bunch of MCP-security tools shipping now (pipelock,
apache/casbin-gateway, apisec/mcp-audit, hyprmcp/mcp-gateway), but
they're all framework-agnostic proxies. They sit on the wire and
intercept JSON-RPC. None of them can see *your code* — the
`@app.delete("/api/admin/users/{user_id}")` decorator three steps
upstream from the wire. So they can't tell you "you're about to ship
admin access to an LLM".

mcp-rampart is the embedded layer that does that. FastAPI-only today.
Node.js (Hono/Express/Fastify) next.

**Stack**

- pure regex + introspection (no ML classifier)
- ~1500 lines of code, MIT
- 56-test pytest suite, CI on each PR
- Python 3.10+

Repo: https://github.com/miloudbelarebia/mcp-rampart
PyPI: https://pypi.org/project/mcp-rampart/

Happy to take feedback, especially on the pattern catalogue. There's a
dedicated issue template for "this should have been flagged".
```

---

## Reddit r/LocalLLaMA / r/MachineLearning

Same body as r/Python, but reframe the hook:

```
Title: A library that audits FastAPI MCP servers and blocks prompt-injection in tool calls (open source, MIT)

Hook paragraph:

If you ship MCP servers (or you've followed the recent Linux Foundation
governance handoff / 97M installs per month figure), you've probably
noticed: there's no library that audits what *you* are about to expose
to a language model from inside your own server. There are gateways
and firewalls on the wire, but nothing code-side. mcp-rampart fills
that gap. Eight audit checks + 27 injection patterns. Three lines to
wire in.

[rest of the post]
```

---

## Demo recording — 60-second script

Camera on terminal. Cursor at top of empty file.

```
00:00  Open empty Python file. Title: "Mealie MCP server, before mcp-rampart"
00:05  Type minimal Mealie-like FastAPI app (or scroll if pre-typed)
00:15  Show: from fastapi_mcp import FastApiMCP — wire it up the "naive" way
00:25  Run the server. Connect Claude Desktop. Show that /api/admin/users
       is callable from Claude.
00:35  PAUSE. Voiceover: "This shouldn't have shipped."
00:40  Cut to: pip install mcp-rampart
00:45  Replace one block with: rampart = MCPRampart(app)
       rampart.audit().print_text()
       if report.has_blockers(): raise SystemExit(1)
00:55  Run. Server refuses to start.
       Terminal shows the audit report:
       🔴 [CRITICAL] /api/admin/users …
01:00  Tagline overlay: "mcp-rampart. one line audit. one line guardrail.
       97M MCP installs / month. someone has to audit what they expose."
```

---

## Launch sequence — recommended order

| Hour | Channel | What to post |
|---|---|---|
| **T0** | PyPI | (already published) |
| T0 | GitHub | (already pushed) |
| T0 + 0h | Personal blog / site | A real post explaining the layered MCP-security map and where mcp-rampart fits |
| T0 + 2h | LinkedIn | Post above. **Personal account.** Tag MCP-related people you know. |
| T0 + 4h | X / Twitter | 3-tweet thread above |
| T0 + 1d | r/Python | Post above (Tuesdays/Wednesdays 10am ET get most upvotes) |
| T0 + 2d | Hacker News | Show HN post |
| T0 + 3-5d | r/LocalLLaMA | Variant of the r/Python post |
| T0 + 1w | Discord (MCP server) | Casual share with the case-study Auth0 finding |

Wait between channels to give each one space. Resist the urge to
cross-post on the same day.

---

## Numbers to track after launch

| Metric | Where to find it |
|---|---|
| PyPI downloads / day | https://pypistats.org/packages/mcp-rampart |
| GitHub stars | repo header |
| Issues opened | repo Issues tab |
| New injection patterns submitted | `[detection]` label on issues |
| External writeups / mentions | Google Alert + brand monitor |

---

## What to do with the first 10 stars

Send a thank-you DM. Ask one specific question: "what made you star? what's
missing for you to use it?" — best free customer research you'll get.

---

## What to NOT say

- "the only" — we're already the only at layer 4, you don't have to repeat it.
- "killer feature" — let the case-study speak.
- "AI-powered" / "GPT-powered" — the detector is regex, not ML. Don't oversell.
- Stars from your own multi-accounts. Won't help and is detectable.
