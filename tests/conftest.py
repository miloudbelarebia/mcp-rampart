"""Shared fixtures for the mcp-rampart test suite."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ── App fixtures ────────────────────────────────────────────────────────


class _User(BaseModel):
    id: int
    name: str


class _UserPII(BaseModel):
    id: int
    name: str
    email: str
    phone: str
    address: str


@pytest.fixture
def safe_app() -> FastAPI:
    """A small FastAPI app with no security issues — should audit clean."""
    app = FastAPI(title="Safe")

    @app.get("/api/users/{user_id}", response_model=_User)
    async def get_user(user_id: int):
        """Get a user by their ID."""
        return _User(id=user_id, name="alice")

    @app.get("/api/users", response_model=list[_User])
    async def list_users():
        """List all users."""
        return []

    @app.post("/api/users", response_model=_User)
    async def create_user(payload: _User):
        """Create a new user."""
        return payload

    return app


@pytest.fixture
def risky_app() -> FastAPI:
    """A FastAPI app that should trigger every audit category."""
    app = FastAPI(title="Risky")

    # CRITICAL — auth endpoint
    @app.post("/api/auth/login")
    async def login(password: str):
        """Login with credentials."""
        return {"token": "x"}

    # CRITICAL — admin endpoint
    @app.delete("/api/admin/users/{user_id}")
    async def del_user(user_id: int):
        return {}  # NO docstring → HIGH

    # HIGH — PII in response
    @app.get("/api/users/{user_id}/profile", response_model=_UserPII)
    async def profile(user_id: int):
        """Get a user's full profile."""
        raise HTTPException(404)

    # LOW — 3+ untyped params
    @app.get("/api/search")
    async def search(q, role, sort, page):
        """Search across the catalogue."""
        return {}

    # MEDIUM — destructive PUT
    @app.put("/api/notes/{note_id}")
    async def update(note_id: int):
        """Update a note."""
        return {}

    return app
