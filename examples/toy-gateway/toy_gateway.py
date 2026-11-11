"""A deliberately simple stdio MCP gateway: a worked example for `mcp-lab score`.

It does what many published gateways do, and no more: an allow list of tool-name
patterns, and an audit log with a keyless SHA-256 hash chain plus a `verify`
command. Scoring it shows what that design does and does not stop.

    python toy_gateway.py run --allow 'crm.*' --log audit.jsonl -- <upstream command...>
    python toy_gateway.py verify audit.jsonl
"""

import argparse
import fnmatch
import hashlib
import json
import os
import sys
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

GENESIS = "0" * 64


def _hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def append(log: Path, record: dict) -> None:
    lines = log.read_text().splitlines() if log.exists() else []
    prev = json.loads(lines[-1])["hash"] if lines else GENESIS
    entry = {"seq": len(lines) + 1, **record, "prev_hash": prev}
    entry["hash"] = _hash(entry)
    with log.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def verify(log: Path) -> int:
    prev = GENESIS
    for n, line in enumerate(log.read_text().splitlines(), 1):
        e = json.loads(line)
        if e.get("seq") != n or e.get("prev_hash") != prev or e.get("hash") != _hash(e):
            print(f"FAIL: chain broken at line {n}")
            return 1
        prev = e["hash"]
    print(f"OK: {n if prev != GENESIS else 0} entries")
    return 0


async def run(allow: list[str], log: Path, upstream: list[str]) -> None:
    params = StdioServerParameters(command=upstream[0], args=upstream[1:], env=dict(os.environ))
    async with Client(params) as up:

        async def list_tools(ctx: ServerRequestContext, p: PaginatedRequestParams | None):
            return ListToolsResult(tools=(await up.list_tools()).tools)

        async def call_tool(ctx: ServerRequestContext, p: CallToolRequestParams):
            allowed = any(fnmatch.fnmatch(p.name, pat) for pat in allow)
            append(log, {"tool": p.name, "decision": "allow" if allowed else "deny"})
            if not allowed:
                text = f"denied: {p.name} is not allowed"
                return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)
            return await up.call_tool(p.name, p.arguments or {})

        server = Server("toy-gateway", on_list_tools=list_tools, on_call_tool=call_tool)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--allow", action="append", default=[])
    r.add_argument("--log", type=Path, required=True)
    r.add_argument("upstream", nargs=argparse.REMAINDER)
    v = sub.add_parser("verify")
    v.add_argument("log", type=Path)
    a = ap.parse_args()
    if a.cmd == "verify":
        sys.exit(verify(a.log))
    upstream = a.upstream[1:] if a.upstream[:1] == ["--"] else a.upstream
    anyio.run(run, a.allow, a.log, upstream)


if __name__ == "__main__":
    main()
