---
name: Bug report
about: Something doesn't work as documented
title: '[bug] '
labels: bug
assignees: ''
---

## What you ran

Minimal FastAPI app + the call against `/mcp`:

```python
from fastapi import FastAPI
from mcp_rampart import MCPRampart

app = FastAPI()
@app.get("/api/x")
async def x(): return {}

rampart = MCPRampart(app)
# ...
```

## What you expected

## What you got

## Environment

- `mcp-rampart` version: `pip show mcp-rampart`
- Python: `python --version`
- FastAPI:
- OS:
