"""Adapter for this repo's reference gateway (HTTP, HMAC chain + anchor).

Scored as an attacker who can write the log and anchor but lacks the HMAC key. A12
here means guessing a key and recomputing the chain with it.
"""

import contextlib
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx2
import rfc8785
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from mcp_lab.harness import ARG_RULES, UPSTREAM, Gateway


def _jcs(e: dict) -> str:
    return rfc8785.dumps(e).decode()


def _entries(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def _write_lines(p: Path, lines: list[str]) -> None:
    p.write_text("".join(x + "\n" for x in lines))


def _tamper_target(n: int) -> int:
    return n // 2


KEY_HEX = "ab" * 32
USER_TOKEN = "user-token-harness"


@contextlib.asynccontextmanager
async def _reference(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    from mcp_lab.gateway.identity import hash_token

    (d / "key").write_text(KEY_HEX)
    sessions = {"sessions": [{"principal": "alice", "role": "user", "token_sha256": ""}]}
    sessions["sessions"][0]["token_sha256"] = hash_token(USER_TOKEN)
    (d / "sessions.yaml").write_text(json.dumps(sessions))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    argv = [str(Path(sys.executable).parent / "mcp-lab-gateway"), "serve"]
    argv += ["--upstream", shlex.join(UPSTREAM), "--sessions", str(d / "sessions.yaml")]
    argv += ["--key-file", str(d / "key"), "--log", str(d / "audit.jsonl")]
    argv += ["--arg-rules", str(ARG_RULES)]
    argv += ["--anchor", str(d / "head.json"), "--port", str(port), "--heartbeat", "3600"]
    for k, v in env.items():
        argv += ["--upstream-env", f"{k}={v}"]
    proc = subprocess.Popen(argv, cwd=d, env=dict(os.environ))
    try:
        for _ in range(150):
            with contextlib.suppress(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            time.sleep(0.1)
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {USER_TOKEN}"})
        async with Client(
            streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http)
        ) as c:  # noqa: E501
            yield c
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _reference_verify(d: Path) -> tuple[bool, str]:
    from mcp_lab.gateway.audit import FileAnchor, verify_log

    r = verify_log(d / "audit.jsonl", bytes.fromhex(KEY_HEX), FileAnchor(d / "head.json").read())
    first = r.first_issue
    return r.ok, "OK" if r.ok else f"{first.kind} at seq {first.seq}"


def _reference_forge(d: Path) -> None:
    """Without the key the attacker can only guess one; recompute with the guess."""
    from mcp_lab.gateway.audit import FileAnchor, Head
    from mcp_lab.gateway.audit.chain import GENESIS_MAC, compute_mac

    p, guess = d / "audit.jsonl", b"\x00" * 32
    es = _entries(p)
    es[_tamper_target(len(es))]["type"] += "-tampered"
    prev = GENESIS_MAC
    for e in es:
        e["prev_mac"] = prev
        e["mac"] = prev = compute_mac(guess, e)
    _write_lines(p, [_jcs(e) for e in es])
    FileAnchor(d / "head.json").write(Head(seq=es[-1]["seq"], mac=es[-1]["mac"]))


REFERENCE = Gateway(
    name="reference",
    version="this repo",
    transport="http",
    connect=_reference,
    log=lambda d: d / "audit.jsonl",
    verify=_reference_verify,
    forge=_reference_forge,
    dump=_jcs,
    caveats=["Scored as an attacker who can write the log and anchor but lacks the HMAC "
             "key. With the key in reach it loses every log attack: see the colocated "
             "profile in scorecard.md."],
)  # fmt: skip
