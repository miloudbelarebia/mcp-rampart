# Security policy

mcp-rampart is itself a security project. If you find a way to defeat
the audit or the guardrail — or any other security issue in the
package — we'd like to know.

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Instead, email:

> **contact@miloudbelarebia.com**

Include enough detail for us to reproduce: a minimal FastAPI app, the
payload that bypasses the guardrail, or the audit case that should
have flagged but didn't.

We aim to acknowledge within **3 business days** and to ship a fix or
a documented mitigation within **14 days** for confirmed issues.

## Scope

The following count as in-scope security issues:

- A prompt-injection pattern that's clearly malicious and the guardrail
  fails to flag at HIGH or BLOCK at default policy.
- An audit-time check that misses a clearly dangerous route (admin
  endpoint exposed, PII leaking response, etc.) on the current target
  framework (FastAPI).
- Any path that lets a `tools/call` request bypass the configured
  policy.
- Information disclosure via the `_mcp_rampart` diagnostic block on a
  blocked response (e.g. leaking server internals beyond what's
  intentionally documented).

Out of scope:

- Generic FastAPI / Starlette / Pydantic bugs (report upstream).
- Issues in the consumer application's routes that mcp-rampart didn't
  flag because they fall outside its declared check categories. (We're
  happy to add new categories — open an issue.)
- Pattern-evasion via novel jailbreaks not yet known publicly: please
  share so we can add the pattern, but we don't treat this as a
  vulnerability in mcp-rampart itself.

## Supported versions

| Version | Status        |
|---------|---------------|
| 0.4.x   | Supported     |
| 0.3.x   | Security fixes only |
| < 0.3   | End of life   |

## Disclosure timeline

1. You email us privately with reproduction steps.
2. We confirm receipt within 3 business days.
3. We work on a fix and coordinate a disclosure date with you.
4. We publish a patched release and a public advisory crediting you
   (unless you prefer anonymity).
5. Detailed technical write-ups are welcome after the fix is out.

Thank you for keeping the agentic web safer.
