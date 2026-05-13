# MCPRampart Case Studies — Real Public FastAPI Projects

This directory contains audit results from running `bridge.audit()` on real public FastAPI projects on GitHub.

The goal: prove that MCPRampart catches concrete security issues in code that thousands of developers already use, not hypothetical ones.

## TL;DR

| Project | Stars | Routes | 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | Verdict |
|---|--:|--:|--:|--:|--:|--:|---|
| [fastapi_mcp/examples/01_basic_usage_example](./01-fastapi-mcp-examples.md) | 11.9k | 6 | 0 | 0 | 2 | 0 | ✅ PASS |
| [fastapi_mcp/examples/02_full_schema_description](./01-fastapi-mcp-examples.md) | 11.9k | 6 | 0 | 0 | 2 | 0 | ✅ PASS |
| [fastapi_mcp/examples/04_separate_server](./01-fastapi-mcp-examples.md) | 11.9k | 6 | 0 | 0 | 2 | 0 | ✅ PASS |
| [fastapi_mcp/examples/08_auth_token_passthrough](./01-fastapi-mcp-examples.md) | 11.9k | 7 | 0 | 1 | 2 | 0 | ✅ PASS |
| **[fastapi_mcp/examples/09_auth_example_auth0](./01-fastapi-mcp-examples.md)** | **11.9k** | **5** | **3** | **6** | **0** | **1** | **❌ BLOCK** |

## Headline finding

> **The official Auth0 example of `fastapi_mcp` — the most popular FastAPI-to-MCP library (11.9k ⭐) — exposes `/oauth/authorize`, `/oauth/register`, and `/.well-known/oauth-authorization-server` to LLM clients by default.**
>
> An MCP client like Claude Desktop, if configured against this server, would see those endpoints listed as callable tools.
>
> MCPRampart catches all three in `bridge.audit()` and `has_blockers()` returns `True`, preventing the server from starting.

This is exactly the failure mode MCPRampart was built to prevent: **a developer ships an "MCP-enabled" version of their app without realising authentication endpoints became LLM tools in the process**.

## Methodology

Each project was:
1. Cloned with `git clone --depth=1 …`
2. Required deps installed in a fresh venv
3. Audited with:
   ```python
   from mcp_rampart import MCPRampart
   bridge = MCPRampart(their_app, include_paths=['/*'])  # expose everything
   report = bridge.audit()
   report.print_text()
   ```

`include_paths=['/*']` was used to capture the worst-case scenario: a developer who copy-pastes a tutorial without tightening filters.

## Reproduce locally

```bash
git clone https://github.com/miloudbelarebia/mcp-rampart
cd mcp-rampart
pip install -e .

git clone --depth=1 https://github.com/tadata-org/fastapi_mcp.git /tmp/fastapi_mcp
cd /tmp/fastapi_mcp
pip install fastapi-mcp pydantic-settings httpx

AUTH0_DOMAIN=dummy.auth0.com AUTH0_AUDIENCE=https://api/ \
AUTH0_CLIENT_ID=x AUTH0_CLIENT_SECRET=x \
python -c "
import sys; sys.path.insert(0, 'examples')
from examples import auth_example_auth0 as ex  # 09_auth_example_auth0
from mcp_rampart import MCPRampart
report = MCPRampart(ex.app, include_paths=['/*']).audit()
report.print_text()
print('blockers:', report.has_blockers())
"
```

You should see 3 CRITICAL findings and a `blockers: True` verdict.
