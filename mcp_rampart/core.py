"""
MCPRampart — Core module (MCP server + audit + runtime guardrail)

Introspects a FastAPI application and exposes its routes as MCP tools,
with a pre-flight security audit (see `audit.py`) to catch dangerous
exposures before they reach LLM clients.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from fastapi import FastAPI
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.routing import Route

logger = logging.getLogger("mcp_rampart")


class ToolCategory(str, Enum):
    """Auto-detected tool categories based on HTTP method and path patterns."""
    QUERY = "query"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ACTION = "action"


@dataclass
class DiscoveredRoute:
    """A route discovered from the FastAPI application."""
    path: str
    method: str
    name: str
    summary: str
    description: str
    parameters: dict[str, Any]
    request_body_schema: dict[str, Any] | None
    response_schema: dict[str, Any] | None
    category: ToolCategory
    tags: list[str]
    handler: Callable
    is_excluded: bool = False


@dataclass
class MCPTool:
    """An MCP tool generated from a discovered route."""
    name: str
    description: str
    input_schema: dict[str, Any]
    route: DiscoveredRoute


class MCPRampart:
    """
    Security-aware MCP connector for FastAPI applications.

    Introspects the app's routes and exposes them as MCP tools that
    any LLM client (Claude, ChatGPT, Gemini) can discover and use.
    Includes a pre-flight `audit()` method to catch dangerous exposures
    (admin endpoints, sensitive params, PII-leaking responses) before
    your API meets a language model.

    Usage:
        app = FastAPI()
        rampart = MCPRampart(app)

        # Run security audit before deploying
        report = rampart.audit()
        if report.has_blockers():
            report.print_text()
            raise SystemExit(1)

    Advanced:
        rampart = MCPRampart(
            app,
            name="My App",
            include_paths=["/api/*"],
            exclude_paths=["/api/admin/*", "/api/auth/*"],
            max_tools=30,
        )
    """

    def __init__(
        self,
        app: FastAPI,
        *,
        name: str | None = None,
        version: str | None = None,
        description: str | None = None,
        include_paths: list[str] | None = None,
        exclude_paths: list[str] | None = None,
        max_tools: int = 50,
        mcp_endpoint: str = "/mcp",
    ):
        self.app = app
        self.name = name or app.title or "MCPRampart Server"
        self.version = version or getattr(app, "version", "1.0.0")
        self.description = description or app.description or f"MCP server for {self.name}"
        # Distinguish "not provided" (use defaults) from "explicitly empty" (no filter)
        self.include_paths = ["/api/*"] if include_paths is None else include_paths
        self.exclude_paths = [
            "*/docs*", "*/redoc*", "*/openapi*", "*/mcp*",
            "*/auth/*", "*/token*",
        ] if exclude_paths is None else exclude_paths
        self.max_tools = max_tools
        self.mcp_endpoint = mcp_endpoint

        # Discovered state
        self._routes: list[DiscoveredRoute] = []
        self._tools: list[MCPTool] = []

        # Optional runtime guardrail (configured via enable_guardrails())
        self._guardrail: Any = None  # mcp_rampart.runtime.Guardrail when enabled

        # Auto-discover on init
        self._discover_routes()
        self._generate_tools()
        self._mount_mcp_endpoint()

        logger.info(
            f"MCPRampart initialized: {len(self._tools)} tools "
            f"discovered from {len(self._routes)} routes"
        )

    # ── Route Discovery ──────────────────────────────────────────────

    def _discover_routes(self) -> None:
        """Introspect the FastAPI app and discover all API routes."""
        for route in self.app.routes:
            if not isinstance(route, APIRoute):
                continue

            for method in route.methods:
                if method.upper() in ("HEAD", "OPTIONS"):
                    continue

                path = route.path

                # Check include/exclude patterns
                if not self._path_matches(path, self.include_paths):
                    continue
                if self._path_matches(path, self.exclude_paths):
                    continue

                discovered = DiscoveredRoute(
                    path=path,
                    method=method.upper(),
                    name=route.name or self._generate_name(method, path),
                    summary=self._extract_summary(route),
                    description=self._extract_description(route),
                    parameters=self._extract_parameters(route),
                    request_body_schema=self._extract_request_body(route),
                    response_schema=self._extract_response_schema(route),
                    category=self._categorize_route(method, path),
                    tags=list(route.tags) if route.tags else [],
                    handler=route.endpoint,
                )
                self._routes.append(discovered)

    def _path_matches(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns."""
        for pattern in patterns:
            regex = pattern.replace("*", ".*")
            if re.match(regex, path):
                return True
        return False

    def _categorize_route(self, method: str, path: str) -> ToolCategory:
        """Categorize a route based on HTTP method and path patterns."""
        method = method.upper()
        if method == "GET":
            return ToolCategory.QUERY
        elif method == "POST":
            if any(kw in path.lower() for kw in ["search", "query", "filter"]):
                return ToolCategory.QUERY
            return ToolCategory.CREATE
        elif method in ("PUT", "PATCH"):
            return ToolCategory.UPDATE
        elif method == "DELETE":
            return ToolCategory.DELETE
        return ToolCategory.ACTION

    # ── Schema Extraction ────────────────────────────────────────────

    def _extract_summary(self, route: APIRoute) -> str:
        """Extract summary from route or its handler docstring."""
        if route.summary:
            return route.summary
        if route.endpoint.__doc__:
            first_line = route.endpoint.__doc__.strip().split("\n")[0]
            return first_line
        return self._humanize_name(route.name or "")

    def _extract_description(self, route: APIRoute) -> str:
        """Extract full description from route or handler docstring."""
        if route.description:
            return route.description
        if route.endpoint.__doc__:
            return route.endpoint.__doc__.strip()
        return ""

    def _extract_parameters(self, route: APIRoute) -> dict[str, Any]:
        """Extract path and query parameters from the route."""
        params = {}
        sig = inspect.signature(route.endpoint)

        # Path parameters
        path_params = re.findall(r"\{(\w+)\}", route.path)

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "request", "response", "db", "session"):
                continue
            # Skip dependency injection params (they have complex defaults)
            if param_name.startswith("_"):
                continue

            param_info: dict[str, Any] = {
                "required": param.default is inspect.Parameter.empty,
            }

            # Determine type
            annotation = param.annotation
            if annotation != inspect.Parameter.empty:
                param_info["type"] = self._python_type_to_json(annotation)
            else:
                param_info["type"] = "string"

            if param_name in path_params:
                param_info["location"] = "path"
            else:
                param_info["location"] = "query"

            if param.default not in (inspect.Parameter.empty, None):
                param_info["default"] = param.default

            params[param_name] = param_info

        return params

    def _extract_request_body(self, route: APIRoute) -> dict[str, Any] | None:
        """Extract request body schema from Pydantic models."""
        sig = inspect.signature(route.endpoint)
        for param_name, param in sig.parameters.items():
            annotation = param.annotation
            if annotation == inspect.Parameter.empty:
                continue
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                return self._pydantic_to_json_schema(annotation)
        return None

    def _extract_response_schema(self, route: APIRoute) -> dict[str, Any] | None:
        """Extract response schema from route's response_model."""
        if route.response_model:
            if isinstance(route.response_model, type) and issubclass(
                route.response_model, BaseModel
            ):
                return self._pydantic_to_json_schema(route.response_model)
        return None

    def _pydantic_to_json_schema(self, model: type[BaseModel]) -> dict[str, Any]:
        """Convert a Pydantic model to JSON Schema."""
        try:
            return model.model_json_schema()
        except Exception:
            return {"type": "object"}

    def _python_type_to_json(self, annotation: Any) -> str:
        """Map Python types to JSON Schema types."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }
        origin = getattr(annotation, "__origin__", None)
        if origin is not None:
            annotation = origin
        return type_map.get(annotation, "string")

    # ── Tool Generation ──────────────────────────────────────────────

    def _generate_tools(self) -> None:
        """Generate MCP tools from discovered routes."""
        for route in self._routes:
            tool_name = self._route_to_tool_name(route)
            tool_description = self._route_to_tool_description(route)
            input_schema = self._route_to_input_schema(route)

            tool = MCPTool(
                name=tool_name,
                description=tool_description,
                input_schema=input_schema,
                route=route,
            )
            self._tools.append(tool)

        # Respect max_tools limit — prioritize GET routes first
        if len(self._tools) > self.max_tools:
            self._tools.sort(
                key=lambda t: (
                    0 if t.route.category == ToolCategory.QUERY else 1,
                    t.name,
                )
            )
            self._tools = self._tools[: self.max_tools]

    def _route_to_tool_name(self, route: DiscoveredRoute) -> str:
        """Generate a clean, LLM-friendly tool name."""
        # Use the route's operation name or generate from method + path
        name = route.name
        if not name:
            name = self._generate_name(route.method, route.path)

        # Clean up: replace hyphens, remove api prefix
        name = name.replace("-", "_").replace(".", "_")
        name = re.sub(r"^(api_|v\d+_)", "", name)

        return name[:64]  # MCP tool names have length limits

    def _route_to_tool_description(self, route: DiscoveredRoute) -> str:
        """Generate a rich, LLM-friendly tool description."""
        parts = []

        if route.summary:
            parts.append(route.summary)

        parts.append(f"[{route.method} {route.path}]")

        if route.description and route.description != route.summary:
            parts.append(route.description[:200])

        if route.tags:
            parts.append(f"Tags: {', '.join(route.tags)}")

        return " | ".join(parts)

    def _route_to_input_schema(self, route: DiscoveredRoute) -> dict[str, Any]:
        """Generate JSON Schema for the tool's input parameters."""
        properties: dict[str, Any] = {}
        required: list[str] = []

        # Add path and query parameters
        for name, info in route.parameters.items():
            prop: dict[str, Any] = {"type": info.get("type", "string")}
            if "default" in info:
                prop["default"] = info["default"]
            properties[name] = prop
            if info.get("required", False):
                required.append(name)

        # Add request body
        if route.request_body_schema:
            body_props = route.request_body_schema.get("properties", {})
            body_required = route.request_body_schema.get("required", [])
            properties.update(body_props)
            required.extend(body_required)

        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required

        return schema

    # ── MCP Endpoint ─────────────────────────────────────────────────

    def _mount_mcp_endpoint(self) -> None:
        """Mount MCP protocol endpoints on the FastAPI app."""
        from fastapi import Body
        from fastapi.responses import JSONResponse

        rampart = self

        @self.app.post(self.mcp_endpoint)
        async def mcp_handler(payload: dict = Body(...)):  # noqa: B008
            """MCP JSON-RPC endpoint (Streamable HTTP transport)."""
            response = await rampart._handle_jsonrpc(payload)
            return JSONResponse(content=response)

        @self.app.get(self.mcp_endpoint)
        async def mcp_info():
            """MCP server info endpoint."""
            return {
                "name": rampart.name,
                "version": rampart.version,
                "description": rampart.description,
                "protocol": "MCP",
                "transport": "streamable-http",
                "tools_count": len(rampart._tools),
                "tools": [
                    {"name": t.name, "description": t.description}
                    for t in rampart._tools
                ],
            }

    async def _handle_jsonrpc(self, body: dict[str, Any]) -> dict[str, Any]:
        """Handle MCP JSON-RPC requests."""
        method = body.get("method", "")
        request_id = body.get("id")
        params = body.get("params", {})

        try:
            if method == "initialize":
                result = self._handle_initialize(params)
            elif method == "tools/list":
                result = self._handle_tools_list(params)
            elif method == "tools/call":
                result = await self._handle_tools_call(params)
            elif method == "ping":
                result = {}
            else:
                return self._jsonrpc_error(request_id, -32601, f"Method not found: {method}")
        except Exception as e:
            logger.exception(f"Error handling MCP request: {method}")
            return self._jsonrpc_error(request_id, -32603, str(e))

        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2025-03-26",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            },
        }

    def _handle_tools_list(self, params: dict) -> dict:
        """Handle MCP tools/list request."""
        tools = []
        for tool in self._tools:
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            })
        return {"tools": tools}

    async def _handle_tools_call(self, params: dict) -> dict:
        """Handle MCP tools/call request — execute the actual API route."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        # Find the tool
        tool = next((t for t in self._tools if t.name == tool_name), None)
        if not tool:
            return {
                "content": [{"type": "text", "text": f"Tool not found: {tool_name}"}],
                "isError": True,
            }

        # Runtime guardrail (when enabled via rampart.enable_guardrails())
        if self._guardrail is not None:
            from mcp_rampart.runtime import format_blocked_response
            decision = self._guardrail.check(tool_name, arguments)
            if not decision.allowed:
                return format_blocked_response(decision)

        route = tool.route

        try:
            # Build kwargs for the handler
            kwargs = {}
            sig = inspect.signature(route.handler)
            for param_name, param in sig.parameters.items():
                if param_name in arguments:
                    kwargs[param_name] = arguments[param_name]
                elif param.default is not inspect.Parameter.empty:
                    kwargs[param_name] = param.default

            # Call the handler
            result = route.handler(**kwargs)
            if inspect.isawaitable(result):
                result = await result

            # Serialize result
            if isinstance(result, BaseModel):
                text = result.model_dump_json(indent=2)
            elif isinstance(result, (dict, list)):
                text = json.dumps(result, indent=2, default=str)
            else:
                text = str(result)

            return {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            }
        except Exception as e:
            logger.exception(f"Error calling tool {tool_name}")
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True,
            }

    # ── Utilities ────────────────────────────────────────────────────

    def _generate_name(self, method: str, path: str) -> str:
        """Generate a tool name from HTTP method and path."""
        clean = path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
        clean = re.sub(r"api_", "", clean)
        return f"{method.lower()}_{clean}"

    def _humanize_name(self, name: str) -> str:
        """Convert snake_case to human-readable."""
        return name.replace("_", " ").replace("-", " ").title()

    @staticmethod
    def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    # ── Public API ───────────────────────────────────────────────────

    def exclude(self, path_pattern: str) -> "MCPRampart":
        """Exclude additional paths after initialization."""
        self.exclude_paths.append(path_pattern)
        self._routes = [r for r in self._routes if not self._path_matches(r.path, [path_pattern])]
        self._tools = [t for t in self._tools if not self._path_matches(t.route.path, [path_pattern])]
        return self

    def tool(self, path: str, *, description: str | None = None, name: str | None = None) -> "MCPRampart":
        """Override tool metadata for a specific path."""
        for tool in self._tools:
            if tool.route.path == path:
                if description:
                    tool.description = description
                if name:
                    tool.name = name
                break
        return self

    @property
    def tools(self) -> list[MCPTool]:
        """Get all registered MCP tools."""
        return self._tools

    @property
    def routes(self) -> list[DiscoveredRoute]:
        """Get all discovered routes."""
        return self._routes

    def summary(self) -> str:
        """Get a human-readable summary of the rampart."""
        lines = [
            f"🛡️  MCPRampart: {self.name} v{self.version}",
            f"   {len(self._routes)} routes discovered → {len(self._tools)} MCP tools",
            f"   Endpoint: {self.mcp_endpoint}",
            "",
        ]
        for tool in self._tools:
            lines.append(f"   🔧 {tool.name}: {tool.description[:80]}")
        return "\n".join(lines)

    def audit(self) -> "AuditReport":
        """
        Run a pre-flight security audit of the exposed routes.

        Catches dangerous exposures (admin endpoints, sensitive params,
        PII-leaking responses, missing docstrings, destructive methods)
        BEFORE your API meets a language model.

        Returns:
            AuditReport with severity-tagged findings.

        Example:
            rampart = MCPRampart(app)
            report = rampart.audit()
            if report.has_blockers():
                report.print_text()
                raise SystemExit(1)
        """
        from mcp_rampart.audit import Auditor
        return Auditor().audit(self)

    def enable_guardrails(
        self,
        *,
        policy: str = "block",
        detect_injection: bool = True,
        log_all_calls: bool = True,
        on_block: Optional[Callable] = None,
        on_alert: Optional[Callable] = None,
    ) -> "MCPRampart":
        """
        Enable runtime guardrails on every incoming `tools/call`.

        The guardrail inspects each tool call's arguments for
        prompt-injection patterns, and applies the chosen policy:
          - "block": refuse the call when injection is detected
          - "alert": let it through but log loudly (and call on_alert)
          - "log":   only log (shadow / observability mode)

        Example:
            rampart = MCPRampart(app)
            rampart.enable_guardrails(
                policy="block",
                on_block=lambda d: send_to_security_team(d),
            )

        Inspect what happened later:
            rampart.guardrail.stats()        # → {"total": 42, "blocked": 3, ...}
            rampart.guardrail.recent(10)     # last 10 calls + decisions
        """
        from mcp_rampart.runtime import Guardrail
        self._guardrail = Guardrail(
            policy=policy,
            detect_injection=detect_injection,
            log_all_calls=log_all_calls,
            on_block=on_block,
            on_alert=on_alert,
        )
        logger.info(
            "MCPRampart guardrails enabled (policy=%s, detect_injection=%s)",
            policy, detect_injection,
        )
        return self

    @property
    def guardrail(self):
        """Access the active Guardrail (or None if not enabled)."""
        return self._guardrail
