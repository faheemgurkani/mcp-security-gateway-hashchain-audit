"""End to end: MCP client -> gateway (real process, Streamable HTTP) -> demo tools (stdio)."""

import json
import os
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

import anyio
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from mcp_gateway.audit import FileAnchor, verify_log
from mcp_gateway.identity import hash_token

ROOT = Path(__file__).resolve().parents[2]
KEY_HEX = "ab" * 32
USER_TOKEN, ADMIN_TOKEN = "user-token-xyz", "admin-token-xyz"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def gateway(tmp_path):
    (tmp_path / "key").write_text(KEY_HEX)
    (tmp_path / "sessions.yaml").write_text(
        json.dumps(
            {
                "sessions": [
                    {"principal": "alice", "role": "user", "token_sha256": hash_token(USER_TOKEN)},
                    {"principal": "root", "role": "admin", "token_sha256": hash_token(ADMIN_TOKEN)},
                ]
            }
        )
    )
    port = _free_port()
    ledger = tmp_path / "ledger.jsonl"
    cli = Path(sys.executable).parent / "mcp-gateway"
    proc = subprocess.Popen(
        [
            str(cli),
            "serve",
            "--upstream",
            shlex.join([sys.executable, "-m", "tools.demo_server.server"]),
            "--upstream-env",
            f"DEMO_LEDGER={ledger}",
            "--upstream-env",
            "DEMO_RUG_PULL_AFTER=4",
            "--sessions",
            str(tmp_path / "sessions.yaml"),
            "--key-file",
            str(tmp_path / "key"),
            "--log",
            str(tmp_path / "audit.jsonl"),
            "--anchor",
            str(tmp_path / "head.json"),
            "--port",
            str(port),
            "--heartbeat",
            "0.5",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("gateway did not start")
    yield {"url": f"http://127.0.0.1:{port}/mcp", "dir": tmp_path, "ledger": ledger}
    proc.terminate()
    proc.wait(timeout=10)


def _client(url: str, token: str | None) -> Client:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30, read=300))
    return Client(streamable_http_client(url, http_client=http))


def _text(result) -> str:
    return result.content[0].text


def _log(d: Path) -> list[dict]:
    return [json.loads(line) for line in (d / "audit.jsonl").read_text().splitlines()]


async def test_pipeline_end_to_end(gateway):
    url, d = gateway["url"], gateway["dir"]

    async with _client(url, USER_TOKEN) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert names == {"crm.lookup", "crm.update"}  # admin tools hidden from users

        ok = await c.call_tool("crm.lookup", {"customer_id": "C1001"})
        assert not ok.is_error and "Ada" in _text(ok)

        # A8 confused deputy
        r = await c.call_tool("admin.delete_user", {"user_id": "U2001"})
        assert r.is_error and "may not call" in _text(r)
        # A7 impersonation via request field
        r = await c.call_tool("crm.lookup", {"customer_id": "C1001", "role": "admin"})
        assert r.is_error and "identity fields" in _text(r)
        # A9 smuggled / malformed parameters
        r = await c.call_tool(
            "crm.update", {"customer_id": "C1001", "field": "password", "value": "x"}
        )
        assert r.is_error and "invalid arguments" in _text(r)

    # A7 forged token
    async with _client(url, "forged") as c:
        assert (await c.list_tools()).tools == []
        r = await c.call_tool("crm.lookup", {"customer_id": "C1001"})
        assert r.is_error and "session token" in _text(r)

    async with _client(url, ADMIN_TOKEN) as c:
        r = await c.call_tool("admin.delete_user", {"user_id": "U2001"})
        assert not r.is_error

    # A10 rug pull: after 4 upstream calls crm.lookup's description changes
    async with _client(url, USER_TOKEN) as c:
        for _ in range(3):
            await c.call_tool("crm.lookup", {"customer_id": "C1001"})
        r = await c.call_tool("crm.lookup", {"customer_id": "C1001"})
        assert r.is_error and "definition changed" in _text(r)

    await anyio.sleep(1.2)  # let at least two heartbeats land
    entries = _log(d)
    types = [e["type"] for e in entries]
    assert types[0] == "proxy_start"
    for t in (
        "call_denied",
        "impersonation_attempt",
        "auth_failed",
        "tool_definition_changed",
        "call_request",
        "call_result",
        "heartbeat",
    ):
        assert t in types, t

    # Ground truth: only allowed calls reached the tool server.
    ledger = [json.loads(x) for x in gateway["ledger"].read_text().splitlines()]
    executed = [x["tool"] for x in ledger]
    assert executed.count("admin.delete_user") == 1  # only the admin's call
    assert len(executed) == types.count("call_request")  # every execution was logged

    report = verify_log(
        d / "audit.jsonl",
        bytes.fromhex(KEY_HEX),
        FileAnchor(d / "head.json").read(),
        max_gap_ms=5_000,
    )
    assert report.ok, report.issues
