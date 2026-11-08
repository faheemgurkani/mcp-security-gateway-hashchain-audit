"""Reference gateway: Streamable HTTP in (agent zone), stdio out (tool zone).

Every tools/call runs this pipeline, and every outcome is logged:

    authenticate -> reject identity fields -> pin check -> policy -> validate
      -> log call_request (fail closed) -> forward -> log call_result

A denial is logged before it is returned. If the request can't be logged,
the call is not forwarded: completeness beats availability.
"""

import contextlib
import hashlib
import shlex
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import anyio
import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from starlette.applications import Starlette

from mcp_gateway.audit import AuditChain, AuditWriteError
from mcp_gateway.audit.canonical import canonical
from mcp_gateway.audit.heartbeat import run_heartbeat
from mcp_gateway.identity import Principal, SessionRegistry, find_impersonation_fields
from mcp_gateway.policy import Policy, ToolPins, tool_fingerprint
from mcp_gateway.validation import ArgumentError, validate_arguments


@dataclass
class GatewayConfig:
    upstream_command: str
    policy: Policy
    sessions: SessionRegistry
    chain: AuditChain
    heartbeat_s: float = 5.0
    upstream_env: dict[str, str] | None = None
    upstream_token: str | None = None  # gateway's own credential to the tool zone
    allowed_hosts: list[str] | None = None  # Host-header allowlist (DNS-rebinding protection)


def _deny(reason: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=f"denied by gateway: {reason}")], is_error=True
    )


def _bearer(ctx: ServerRequestContext) -> str | None:
    request = ctx.request
    if request is None:
        return None
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else None


def _fingerprints(tools: list[Tool]) -> dict[str, str]:
    return {t.name: tool_fingerprint(t.name, t.description, t.input_schema) for t in tools}


class Gateway:
    def __init__(self, cfg: GatewayConfig):
        self.cfg = cfg
        self.upstream: Client | None = None
        self.pins: ToolPins | None = None
        self._tools: dict[str, Tool] = {}

    # ---- lifecycle -------------------------------------------------------
    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator["Gateway"]:
        async with Client(self._upstream_transport()) as upstream:
            self.upstream = upstream
            tools = (await upstream.list_tools()).tools
            self._tools = {t.name: t for t in tools}
            self.pins = ToolPins(_fingerprints(tools))
            self.cfg.chain.append(
                "proxy_start",
                {
                    "policy_sha256": self.cfg.policy.sha256,
                    "tools_sha256": self.pins.sha256,
                    "tools": sorted(self._tools),
                    "upstream": self.cfg.upstream_command,
                },
            )
            async with anyio.create_task_group() as tg:
                tg.start_soon(run_heartbeat, self.cfg.chain, self.cfg.heartbeat_s)
                try:
                    yield self
                finally:
                    tg.cancel_scope.cancel()
            self.upstream = None

    def _upstream_transport(self) -> Any:
        """stdio child process, or a Streamable HTTP tool server in the tool zone."""
        cmd = self.cfg.upstream_command
        if cmd.startswith(("http://", "https://")):
            headers = (
                {"Authorization": f"Bearer {self.cfg.upstream_token}"}
                if self.cfg.upstream_token
                else {}
            )
            http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30, read=300))
            return streamable_http_client(cmd, http_client=http)
        argv = shlex.split(cmd)
        return StdioServerParameters(command=argv[0], args=argv[1:], env=self.cfg.upstream_env)

    # ---- helpers ---------------------------------------------------------
    def _log(self, type_: str, payload: dict[str, Any], principal: Principal | None) -> None:
        self.cfg.chain.append(type_, payload, session=None if principal is None else principal.name)

    async def _refresh_pins(self) -> list[str]:
        """Re-list upstream tools and quarantine any whose definition changed (A10)."""
        assert self.upstream is not None and self.pins is not None
        tools = (await self.upstream.list_tools()).tools
        changed = self.pins.check(_fingerprints(tools))
        for name in changed:
            self._log("tool_definition_changed", {"tool": name}, None)
        return changed

    # ---- MCP handlers ----------------------------------------------------
    async def list_tools(
        self, ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        principal = self.cfg.sessions.resolve(_bearer(ctx))
        if principal is None:
            return ListToolsResult(tools=[])
        await self._refresh_pins()
        assert self.pins is not None
        visible = [
            t
            for name, t in self._tools.items()
            if self.pins.allowed(name) and self.cfg.policy.is_visible(principal.role, name)
        ]
        return ListToolsResult(tools=visible)

    async def call_tool(
        self, ctx: ServerRequestContext, params: CallToolRequestParams
    ) -> CallToolResult:
        tool, args = params.name, params.arguments
        principal = self.cfg.sessions.resolve(_bearer(ctx))
        base = {"tool": tool, "args_sha256": hashlib.sha256(canonical(args or {})).hexdigest()}

        def deny(kind: str, reason: str) -> CallToolResult:
            try:
                self._log(kind, {**base, "reason": reason}, principal)
            except AuditWriteError:
                pass  # denying anyway; nothing executed
            return _deny(reason)

        if principal is None:
            return deny("auth_failed", "missing or unknown session token")

        identity_fields = find_impersonation_fields(args)
        if identity_fields:
            return deny("impersonation_attempt", f"identity fields not accepted: {identity_fields}")

        await self._refresh_pins()
        assert self.pins is not None
        if not self.pins.allowed(tool):
            return deny("call_denied", f"tool {tool!r} is unknown or its definition changed")

        decision = self.cfg.policy.decide(principal.role, tool)
        if not decision.allowed:
            return deny("call_denied", decision.reason)

        try:
            clean_args = validate_arguments(tool, args)
        except ArgumentError as e:
            return deny("call_denied", f"invalid arguments: {e}")

        try:
            self._log(
                "call_request", {**base, "role": principal.role, "args": clean_args}, principal
            )
        except AuditWriteError:
            return _deny("audit log unavailable; failing closed")

        assert self.upstream is not None
        result = await self.upstream.call_tool(tool, clean_args)
        result_payload = result.model_dump(mode="json", exclude_none=True)
        try:
            self._log(
                "call_result",
                {
                    "tool": tool,
                    "is_error": bool(result.is_error),
                    "result_sha256": hashlib.sha256(canonical(result_payload)).hexdigest(),
                    "result": result_payload,
                },
                principal,
            )
        except AuditWriteError:
            return _deny("executed, but result could not be logged; result withheld")
        return result


def build_app(cfg: GatewayConfig) -> Starlette:
    gateway = Gateway(cfg)
    server = Server(
        "mcp-gateway-reference",
        on_list_tools=gateway.list_tools,
        on_call_tool=gateway.call_tool,
    )
    security = (
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=cfg.allowed_hosts
        )
        if cfg.allowed_hosts
        else None
    )
    app = server.streamable_http_app(host="0.0.0.0", transport_security=security)
    inner_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a: Starlette) -> AsyncIterator[None]:
        async with gateway.running(), inner_lifespan(a):
            yield

    app.router.lifespan_context = lifespan
    app.state.gateway = gateway
    return app
