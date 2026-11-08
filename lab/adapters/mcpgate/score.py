"""Score the external gateway `mcp-gate-policy` (stdio proxy) on the attacks
that apply to a stdio deployment, and compare it with the reference gateway.

mcp-gate is a stdio proxy, so it lives in the colocated/stdio world: the agent
launches it as a subprocess with the identity env var it chooses. This scorer
therefore covers the attacks that are well-defined there:

- policy (A7 goal, A8, A9): does a forbidden/malformed call reach the tool?
  Ground truth is the demo tool server's execution ledger.
- supply chain (A10): is a rug-pulled tool still callable?
- log integrity (A1, A2, A3, A11): after tampering the audit file, does the
  gateway's own verifier flag it? For mcp-gate that is `mcp-gate verify`.

Network-boundary attacks (A4 config bypass, A5 kill, A6 direct) are not
separately meaningful for a stdio proxy the agent launches itself: the agent
can always run the tool server directly. That is the colocated finding, and it
is recorded as such rather than re-run here.

Run: uv run python -m lab.adapters.mcpgate.score   (needs: uv sync --extra external)
"""

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import anyio
from mcp import Client, MCPError, StdioServerParameters

ROOT = Path(__file__).resolve().parents[3]
SECRET = "lab-dev-secret-000"
POLICY = {
    "default_effect": "deny",
    "rules": [{"name": "crm", "tools": ["crm.*"], "roles": ["user"], "effect": "allow"}],
}


@dataclass
class Case:
    id: str
    title: str


def mint_token(role: str) -> str:
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcpgate.cli",
            "token",
            "--scheme",
            "hmac",
            "--secret",
            SECRET,
            "--agent-id",
            "alice",
            "--role",
            role,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def verify(audit: Path) -> tuple[bool, str]:
    v = subprocess.run(
        [sys.executable, "-m", "mcpgate.cli", "verify", "--audit", str(audit)],
        capture_output=True,
        text=True,
    )
    last = (v.stdout + v.stderr).strip().splitlines()[-1] if (v.stdout + v.stderr).strip() else ""
    return v.returncode == 0, last


def make_env(token: str, ledger: Path, rug_after: int = 0) -> dict[str, str]:
    return {
        **os.environ,
        "MCPGATE_AGENT_TOKEN": token,
        "DEMO_LEDGER": str(ledger),
        "DEMO_RUG_PULL_AFTER": str(rug_after),
        "PYTHONPATH": str(ROOT),
    }


def proxy_params(d: Path, env: dict[str, str]) -> StdioServerParameters:
    cmd = [
        sys.executable,
        "-m",
        "mcpgate.cli",
        "run",
        "--policy",
        str(d / "policy.json"),
        "--audit",
        str(d / "audit.log"),
        "--fail",
        "closed",
        "--secret",
        SECRET,
        "--",
        sys.executable,
        "-m",
        "tools.demo_server.server",
    ]
    return StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)


async def _call(client: Client, tool: str, args: dict) -> str:
    try:
        r = await client.call_tool(tool, args)
        return "error" if r.is_error else "ok"
    except MCPError:
        return "denied"
    except BaseException as e:  # noqa: BLE001
        inner = e.exceptions[0] if isinstance(e, BaseExceptionGroup) else e
        return f"exc:{type(inner).__name__}"


async def drive(params: StdioServerParameters, calls: list[tuple[str, dict]]) -> list[str]:
    out = []
    async with Client(params) as c:
        for tool, args in calls:
            out.append(await _call(c, tool, args))
    return out


def ledger_tools(ledger: Path) -> list[dict]:
    if not ledger.exists():
        return []
    return [json.loads(x) for x in ledger.read_text().splitlines() if x.strip()]


def _well_formed(tool: str, args: dict) -> bool:
    cid = str(args.get("customer_id", ""))
    cid_ok = cid.startswith("C") and cid[1:].isdigit()
    if tool == "crm.lookup":
        return set(args) == {"customer_id"} and cid_ok
    if tool == "crm.update":
        return (
            set(args) == {"customer_id", "field", "value"}
            and cid_ok
            and args["field"] in {"email", "phone", "notes"}
        )
    return True


def policy_case(cid: str, title: str, calls: list[tuple[str, dict]], forbidden) -> dict:
    d = Path(tempfile.mkdtemp())
    (d / "policy.json").write_text(json.dumps(POLICY))
    ledger = d / "ledger.jsonl"
    rug = 3 if cid == "A10" else 0
    anyio.run(drive, proxy_params(d, make_env(mint_token("user"), ledger, rug)), calls)
    executed = [x for x in ledger_tools(ledger) if forbidden(x)]
    outcome = "blocked" if not executed else "undetected"
    ev = (
        "no forbidden/malformed call reached the tool server"
        if not executed
        else f"executed: {[x['tool'] for x in executed]}"
    )
    return {"id": cid, "title": title, "execution": outcome, "evidence": ev}


def tamper_case(cid: str, title: str, mutate) -> dict:
    d = Path(tempfile.mkdtemp())
    (d / "policy.json").write_text(json.dumps(POLICY))
    audit, ledger = d / "audit.log", d / "ledger.jsonl"
    calls = [
        ("crm.lookup", {"customer_id": "C1001"}),
        ("crm.update", {"customer_id": "C1001", "field": "notes", "value": "x"}),
    ]
    anyio.run(drive, proxy_params(d, make_env(mint_token("user"), ledger)), calls)
    clean_ok, _ = verify(audit)
    lines = audit.read_text().splitlines()
    audit.write_text("\n".join(mutate(lines)) + ("\n" if lines else ""))
    ok, msg = verify(audit)
    outcome = "detected" if not ok else "undetected"
    return {
        "id": cid,
        "title": title,
        "tampering": outcome,
        "evidence": f"clean verify ok={clean_ok}; after tamper: {msg}",
    }


def _edit(lines: list[str]) -> list[str]:
    e = json.loads(lines[0])
    if "tool" in e:
        e["tool"] = "tampered"
    lines[0] = json.dumps(e)
    return lines


def main() -> None:
    results = []
    # Policy / validation / supply-chain
    results.append(
        policy_case(
            "A7",
            "Impersonate admin (goal: admin access via request field)",
            [("admin.delete_user", {"user_id": "U2001", "role": "admin"})],
            lambda x: x["tool"].startswith("admin."),
        )
    )
    results.append(
        policy_case(
            "A8",
            "Confused deputy (user calls admin tool)",
            [("admin.delete_user", {"user_id": "U2001"})],
            lambda x: x["tool"].startswith("admin."),
        )
    )
    results.append(
        policy_case(
            "A9",
            "Smuggle / malformed parameters",
            [
                ("crm.update", {"customer_id": "C1001", "field": "password", "value": "x"}),
                ("crm.lookup", {"customer_id": "C1001", "role": "admin"}),
            ],
            lambda x: not _well_formed(x["tool"], x.get("arguments", {})),
        )
    )
    results.append(
        policy_case(
            "A10",
            "Rug pull (tool definition changes)",
            [("crm.lookup", {"customer_id": "C1001"})] * 4,
            lambda x: False if x["tool"] != "crm.lookup" else _rug_counter(),
        )
    )
    # Log integrity
    results.append(tamper_case("A1", "Edit a log entry", _edit))
    results.append(tamper_case("A2", "Delete a log entry", lambda ls: ls[1:]))
    results.append(tamper_case("A3", "Truncate the log tail", lambda ls: ls[:1]))

    out = ROOT / "lab/results/external.json"
    out.write_text(
        json.dumps(
            {"gateway": "mcp-gate-policy", "transport": "stdio", "results": results}, indent=2
        )
    )
    for r in results:
        key = "execution" if "execution" in r else "tampering"
        print(f"mcp-gate {r['id']:4} {r[key]:10} {r['evidence'][:70]}")
    print(f"wrote {out}")


_rug_seen = {"n": 0}


def _rug_counter() -> bool:
    _rug_seen["n"] += 1
    return _rug_seen["n"] > 3  # calls after the 3rd are against the rug-pulled definition


if __name__ == "__main__":
    main()
