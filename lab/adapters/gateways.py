"""Gateway definitions for the harness: the reference gateway and external gateways.

Each external gateway is installed in its own virtualenv / node_modules under
``lab/.ext/<name>/`` (git-ignored), never into the project environment, and is
configured as close to least privilege as it allows: a ``user`` may call
``crm.*`` only, admin tools are denied, and its strongest audit option is on.

The A12 forgers re-implement each gateway's *published* hashing scheme. The
forged log is then judged by the gateway's own verifier, so a forger bug can
only make a result look better for the gateway (detected), never worse.
"""

import contextlib
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import unicodedata
from collections.abc import AsyncIterator
from pathlib import Path

import httpx2
import rfc8785
import yaml
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from lab.adapters.harness import ROOT, UPSTREAM, Gateway

EXT = ROOT / "lab/.ext"


def _jcs(e: dict) -> str:
    return rfc8785.dumps(e).decode()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[bool, str]:
    r = subprocess.run(argv, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True,
                       text=True, timeout=60)  # fmt: skip
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _stdio(argv: list[str], d: Path, env: dict[str, str], mode: str = "auto") -> Client:
    params = StdioServerParameters(command=argv[0], args=argv[1:], env={**os.environ, **env}, cwd=d)
    return Client(params, mode=mode)


def _entries(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def _write_lines(p: Path, lines: list[str]) -> None:
    p.write_text("".join(x + "\n" for x in lines))


def _tamper_target(n: int) -> int:
    return n // 2


# ---- reference gateway (this repo) ----------------------------------------------------
KEY_HEX = "ab" * 32
USER_TOKEN = "user-token-harness"


@contextlib.asynccontextmanager
async def _reference(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    from mcp_gateway.identity import hash_token

    (d / "key").write_text(KEY_HEX)
    sessions = {"sessions": [{"principal": "alice", "role": "user", "token_sha256": ""}]}
    sessions["sessions"][0]["token_sha256"] = hash_token(USER_TOKEN)
    (d / "sessions.yaml").write_text(json.dumps(sessions))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    argv = [str(Path(sys.executable).parent / "mcp-gateway"), "serve"]
    argv += ["--upstream", shlex.join(UPSTREAM), "--sessions", str(d / "sessions.yaml")]
    argv += ["--key-file", str(d / "key"), "--log", str(d / "audit.jsonl")]
    argv += ["--anchor", str(d / "head.json"), "--port", str(port), "--heartbeat", "3600"]
    for k, v in env.items():
        argv += ["--upstream-env", f"{k}={v}"]
    proc = subprocess.Popen(argv, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
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
    from mcp_gateway.audit import FileAnchor, verify_log

    r = verify_log(d / "audit.jsonl", bytes.fromhex(KEY_HEX), FileAnchor(d / "head.json").read())
    first = r.first_issue
    return r.ok, "OK" if r.ok else f"{first.kind} at seq {first.seq}"


def _reference_forge(d: Path) -> None:
    """Without the key the attacker can only guess one; recompute with the guess."""
    from mcp_gateway.audit import FileAnchor, Head
    from mcp_gateway.audit.chain import GENESIS_MAC, compute_mac

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


# ---- mcp-gate-policy (PyPI, installed via `uv sync --extra external`) ------------------
MCPGATE_SECRET = "lab-dev-secret-000"


def _mcpgate_cli(*args: str) -> list[str]:
    return [sys.executable, "-m", "mcpgate.cli", *args]


@contextlib.asynccontextmanager
async def _mcpgate(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    policy = {
        "default_effect": "deny",
        "rules": [{"name": "crm", "tools": ["crm.*"], "roles": ["user"], "effect": "allow"}],
    }
    (d / "policy.json").write_text(json.dumps(policy))
    ok, token = _run(
        _mcpgate_cli("token", "--scheme", "hmac", "--secret", MCPGATE_SECRET, "--agent-id",
                     "alice", "--role", "user"),
        d,
    )  # fmt: skip
    argv = _mcpgate_cli("run", "--policy", str(d / "policy.json"), "--audit",
                        str(d / "audit.log"), "--fail", "closed", "--secret", MCPGATE_SECRET,
                        "--", *UPSTREAM)  # fmt: skip
    async with _stdio(argv, d, {**env, "MCPGATE_AGENT_TOKEN": token.splitlines()[-1]}) as c:
        yield c


def _mcpgate_forge(d: Path) -> None:
    p = d / "audit.log"
    es = _entries(p)
    i = _tamper_target(len(es))
    es[i]["tool"] += "-tampered"
    prev = es[i - 1]["hash"] if i else "0" * 64
    for e in es[i:]:
        e["prev_hash"] = prev
        body = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = prev = _sha(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    _write_lines(p, [json.dumps(e, separators=(",", ":"), sort_keys=True) for e in es])


def _version(dist: str, python: str = sys.executable) -> str:
    code = f"import importlib.metadata as m; print(m.version({dist!r}))"
    return subprocess.run([python, "-c", code], capture_output=True, text=True).stdout.strip()


def MCPGATE() -> Gateway:  # noqa: N802 - built lazily: needs the optional extra
    return Gateway(
        name="mcp-gate-policy",
        version=_version("mcp-gate-policy"),
        transport="stdio",
        connect=_mcpgate,
        log=lambda d: d / "audit.log",
        verify=lambda d: _run(_mcpgate_cli("verify", "--audit", str(d / "audit.log")), d),
        forge=_mcpgate_forge,
    )


# ---- shugo (PyPI) -----------------------------------------------------------------------
SHUGO = EXT / "shugo/bin"


def _shugo_env(d: Path) -> dict[str, str]:
    return {"SHUGO_HOME": str(d / "shugo")}


@contextlib.asynccontextmanager
async def _shugo(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    cfg = {
        "version": "0.1",
        "defaults": {"decision": "deny", "on_error": "deny"},
        "upstreams": {"demo": {"command": UPSTREAM[0], "args": UPSTREAM[1:], "env": env}},
        "rules": [
            {"id": "crm", "match": {"server": "demo", "tool": ["crm.*"]}, "decision": "allow"}
        ],  # noqa: E501
    }
    (d / "guardrails.yaml").write_text(yaml.safe_dump(cfg))
    argv = [str(SHUGO / "shugo"), "serve", "--config", str(d / "guardrails.yaml")]
    async with _stdio(argv, d, _shugo_env(d)) as c:
        yield c


def _shugo_canonical(obj: object) -> bytes:
    def norm(o: object) -> object:
        if isinstance(o, str):
            return unicodedata.normalize("NFC", o)
        if isinstance(o, dict):
            return {norm(k): norm(v) for k, v in o.items()}
        if isinstance(o, list):
            return [norm(v) for v in o]
        return o

    return json.dumps(norm(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _shugo_forge(d: Path) -> None:
    p = d / "shugo/audit.log"
    es = _entries(p)
    i = _tamper_target(len(es))
    es[i]["tool"] += "-tampered"
    prev = es[i - 1]["this_hash"] if i else "0" * 64
    for e in es[i:]:
        payload = {k: v for k, v in e.items() if k != "this_hash"}
        payload["prev_hash"] = prev
        e["prev_hash"] = prev
        e["this_hash"] = prev = _sha(prev.encode() + _shugo_canonical(payload))
    _write_lines(p, [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in es])


def SHUGO_GW() -> Gateway:  # noqa: N802
    return Gateway(
        name="shugo",
        version=_version("shugo", str(SHUGO / "python")),
        transport="stdio",
        connect=_shugo,
        log=lambda d: d / "shugo/audit.log",
        verify=lambda d: _run([str(SHUGO / "shugo"), "audit", "verify"], d, _shugo_env(d)),
        forge=_shugo_forge,
        dump=lambda e: json.dumps(e, ensure_ascii=False, sort_keys=True),
        prefix="demo__",
        caveats=["v0.1 has no per-principal identity (on its v0.2 roadmap): the policy is per "
                 "deployment, so A7/A8 test the deployment's allow list."],
    )  # fmt: skip


# ---- mcp-glp-audit-proxy (PyPI, Community edition) ---------------------------------------
GLP = EXT / "mcp-glp-audit-proxy/bin"


@contextlib.asynccontextmanager
async def _glp(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    cfg = {
        "principal": {"id": "alice", "name": "Alice", "role": "operator"},
        "policy": {"allow": ["demo__crm.*"], "deny": [], "write_tools": [],
                   "require_reason_for_writes": False},
        "audit": {"path": str(d / "audit.jsonl"), "fail_closed": True, "body_mode": "full"},
        "retention": {"profile": "minimum"},
        "upstreams": [{"name": "demo", "transport": "stdio", "command": UPSTREAM[0],
                       "args": UPSTREAM[1:], "env": env, "cwd": str(ROOT)}],
    }  # fmt: skip
    (d / "config.json").write_text(json.dumps(cfg))
    argv = [str(GLP / "mcp-glp-audit-proxy"), "--config", str(d / "config.json")]
    # 0.4.0 negotiates spec 2026-07-28 but omits its required `resultType` on tool results,
    # which an SDK 2.3 client rejects; the initialize-era handshake works.
    async with _stdio(argv, d, {}, mode="legacy") as c:
        yield c


def _glp_forge(d: Path) -> None:
    """Re-seal with SHA-256 over RFC 8785 and move the .head sidecar along (its README notes
    that someone who can edit both files can do this; an off-host copy is the control)."""
    p = d / "audit.jsonl"
    es = _entries(p)
    i = _tamper_target(len(es))
    es[i]["tool"] = str(es[i].get("tool")) + "-tampered"
    prev = es[i - 1]["entry_hash"] if i else "0" * 64
    for e in es[i:]:
        e["prev_hash"] = prev
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        e["entry_hash"] = prev = _sha(rfc8785.dumps(body))
    _write_lines(p, [_jcs(e) for e in es])
    head = {"entry_hash": es[-1]["entry_hash"], "seq": es[-1]["seq"]}
    (d / "audit.jsonl.head").write_bytes(rfc8785.dumps(head) + b"\n")


def GLP_GW() -> Gateway:  # noqa: N802
    return Gateway(
        name="mcp-glp-audit-proxy",
        version=_version("mcp-glp-audit-proxy", str(GLP / "python")),
        transport="stdio",
        connect=_glp,
        log=lambda d: d / "audit.jsonl",
        verify=lambda d: _run([str(GLP / "mcp-glp-audit-proxy-verify"), str(d / "audit.jsonl")], d),  # noqa: E501
        forge=_glp_forge,
        dump=_jcs,
        prefix="demo__",
        caveats=["Community edition (signed checkpoints are a Pro feature). Stdio identity "
                 "comes from GLP_PRINCIPAL_* env set by whoever launches it."],
    )  # fmt: skip


# ---- mcp-audit-proxy (npm launcher for a Go binary) ----------------------------------------
MCPAUDIT = EXT / "mcp-audit-proxy/node_modules/.bin/mcp-audit"


@contextlib.asynccontextmanager
async def _mcpaudit(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
    cfg = {
        "mode": "stdio",
        "policy": {
            "rbac": {"default": "deny", "rules": [{"client": "alice", "allow": ["crm.*"]}]},
            "rug_pull_detection": True,
            "poisoning_heuristics": True,
            "state_path": str(d / "state/tools.json"),
        },
        "sinks": {"jsonl": {"path": str(d / "events.jsonl")}},
    }
    (d / "mcp-audit.yaml").write_text(yaml.safe_dump(cfg))
    argv = [str(MCPAUDIT), "run", "--config", str(d / "mcp-audit.yaml"), "--client-id", "alice",
            "--quiet", "--", *UPSTREAM]  # fmt: skip
    async with _stdio(argv, d, env) as c:
        yield c


def MCPAUDIT_GW() -> Gateway:  # noqa: N802
    pkg = EXT / "mcp-audit-proxy/node_modules/mcp-audit-proxy/package.json"
    return Gateway(
        name="mcp-audit-proxy",
        version=json.loads(pkg.read_text())["version"] if pkg.exists() else "?",
        transport="stdio",
        connect=_mcpaudit,
        log=lambda d: d / "events.jsonl",
        verify=None,  # a flight recorder: plain JSONL, no integrity check
        rug_flagged=lambda d: any(
            "rug_pull" in (json.loads(x).get("policy_flags") or [])
            for x in (d / "events.jsonl").read_text().splitlines()
            if x.strip()
        ),
        caveats=["A recorder with detectors, not a tamper-evident log: it does not claim log "
                 "integrity, so A1-A3/A12 show the absence of that feature, not a defect."],
    )  # fmt: skip


ALL = {
    "reference": lambda: REFERENCE,
    "mcp-gate-policy": MCPGATE,
    "shugo": SHUGO_GW,
    "mcp-glp-audit-proxy": GLP_GW,
    "mcp-audit-proxy": MCPAUDIT_GW,
}

# Gateways whose results are held back until the maintainer has been told privately
# (D-013) live in a git-ignored module and are scored to lab/results/raw/.
try:
    from lab.adapters.embargoed import EMBARGOED
except ImportError:
    EMBARGOED = {}
ALL.update(EMBARGOED)
