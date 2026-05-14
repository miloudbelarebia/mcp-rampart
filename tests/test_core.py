"""Smoke tests for the MCPRampart core class."""

from __future__ import annotations

from fastapi import FastAPI

import mcp_rampart
from mcp_rampart import MCPRampart


def test_package_exports_are_complete():
    """All public names declared in __all__ must be importable."""
    for name in mcp_rampart.__all__:
        assert hasattr(mcp_rampart, name), f"missing export: {name}"


def test_version_is_pep440():
    """__version__ must be a PEP 440 version string."""
    import re

    assert re.match(r"^\d+\.\d+\.\d+", mcp_rampart.__version__)


def test_can_construct_on_empty_app():
    """An empty FastAPI app should construct a valid (empty) rampart."""
    app = FastAPI()
    rampart = MCPRampart(app)
    assert rampart.tools == []
    assert rampart.routes == []


def test_routes_are_discovered(safe_app):
    """Routes registered on the FastAPI app must be discovered as tools."""
    rampart = MCPRampart(safe_app)
    assert len(rampart.tools) == 3
    tool_names = {t.name for t in rampart.tools}
    assert "get_user" in tool_names
    assert "list_users" in tool_names
    assert "create_user" in tool_names


def test_exclude_paths_removes_routes(risky_app):
    """exclude_paths should filter out matching routes at init time."""
    rampart = MCPRampart(risky_app, exclude_paths=["*/auth/*", "*/admin/*"])
    paths = {t.route.path for t in rampart.tools}
    assert not any("/auth/" in p for p in paths)
    assert not any("/admin/" in p for p in paths)


def test_max_tools_caps_the_count(risky_app):
    """max_tools=2 must result in at most 2 exposed tools."""
    rampart = MCPRampart(risky_app, max_tools=2)
    assert len(rampart.tools) <= 2


def test_mcp_get_endpoint_returns_server_info(safe_app):
    """GET /mcp must return the server info JSON."""
    from fastapi.testclient import TestClient

    rampart = MCPRampart(safe_app)
    client = TestClient(safe_app)
    r = client.get("/mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["protocol"] == "MCP"
    assert body["tools_count"] == len(rampart.tools)


def test_mcp_post_tools_list(safe_app):
    """POST /mcp with tools/list must return the discovered tools."""
    from fastapi.testclient import TestClient

    MCPRampart(safe_app)
    client = TestClient(safe_app)
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 200
    body = r.json()
    assert "result" in body
    assert len(body["result"]["tools"]) == 3


def test_mcp_post_tools_call_executes_the_handler(safe_app):
    """tools/call should dispatch to the original route handler."""
    from fastapi.testclient import TestClient

    MCPRampart(safe_app)
    client = TestClient(safe_app)
    r = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_user", "arguments": {"user_id": 42}},
        },
    )
    assert r.status_code == 200
    res = r.json()["result"]
    assert res["isError"] is False
    assert "alice" in res["content"][0]["text"]


def test_mcp_post_unknown_method_returns_jsonrpc_error(safe_app):
    """Unknown JSON-RPC method must return error -32601."""
    from fastapi.testclient import TestClient

    MCPRampart(safe_app)
    client = TestClient(safe_app)
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 99, "method": "nope/wat"})
    body = r.json()
    assert "error" in body
    assert body["error"]["code"] == -32601
