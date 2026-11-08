"""Agent-side MCP access, driven by the agent's own config file.

Like a real host (Claude Code, Cursor), the agent reads its MCP server URL
and headers from a JSON config it can edit. Attack A4 edits this file.
"""

import json
import os
from pathlib import Path
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

CONFIG = Path(os.environ.get("AGENT_MCP_CONFIG", "/home/agent/mcp.json"))


def load_server(name: str = "crm") -> dict[str, Any]:
    return json.loads(CONFIG.read_text())["mcpServers"][name]


def connect(
    url: str | None = None, headers: dict[str, str] | None = None, name: str = "crm"
) -> Client:
    server = load_server(name)
    http = httpx2.AsyncClient(
        headers=server.get("headers", {}) if headers is None else headers,
        timeout=httpx2.Timeout(5, read=10),
    )
    return Client(streamable_http_client(url or server["url"], http_client=http))
