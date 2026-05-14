---
name: Missing injection pattern / audit check
about: A clearly dangerous input or route that mcp-rampart didn't flag
title: '[detection] '
labels: detection
assignees: ''
---

## The input mcp-rampart should have caught

For an injection pattern:
```
<paste the argument string here>
```

For an audit check, the smallest FastAPI route that should trigger:
```python
@app.get(...)
async def ...(): ...
```

## Why it's clearly malicious / dangerous

One or two sentences.

## What mcp-rampart returned

```
<paste the audit report or the guardrail decision here>
```

## Suggested category

- Confidence (HIGH / MEDIUM / LOW) or Severity (CRITICAL / HIGH / MEDIUM / LOW):
- Category name:
