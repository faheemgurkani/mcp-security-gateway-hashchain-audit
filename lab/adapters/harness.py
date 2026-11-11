"""One attack harness for every gateway: same tool server, same attacks, same judging.

A gateway is described by a ``Gateway`` (see lab/adapters/README.md for the
contract). The harness wraps the demo tool server with it, drives the attacks
through it as an MCP client, and judges each one from evidence outside the
gateway:

- **execution** (A7-A10): the tool server's own ledger of calls it executed;
- **tampering** (A1-A3, A12): the gateway's *own* verifier, run on a log the
  harness has tampered with.

Every attack runs in a fresh temporary directory with a fresh gateway process.
"""

import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from pathlib import Path

import anyio
from mcp import Client, MCPError

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = [sys.executable, "-m", "tools.demo_server.server"]
ARG_RULES = ROOT / "tools/demo_server/arg-rules.yaml"
RUG_AFTER = 3  # demo server changes crm.lookup's description after this many calls

Connect = Callable[[Path, dict[str, str]], AbstractAsyncContextManager[Client]]


@dataclass
class Gateway:
    name: str
    version: str
    transport: str
    connect: Connect  # (work dir, upstream env) -> MCP client session through the gateway
    log: Callable[[Path], Path]  # where the audit log is
    verify: Callable[[Path], tuple[bool, str]] | None  # the gateway's own integrity check
    forge: Callable[[Path], None] | None = None  # A12: rewrite with the public algorithm
    dump: Callable[[dict], str] = lambda e: json.dumps(e, sort_keys=True, separators=(",", ":"))
    rug_flagged: Callable[[Path], bool] | None = None  # did it raise a rug-pull alarm?
    prefix: str = ""  # how it renames upstream tools, e.g. "demo__"
    caveats: list[str] = field(default_factory=list)


def upstream_env(d: Path, rug: bool = False) -> dict[str, str]:
    return {
        "DEMO_LEDGER": str(d / "ledger.jsonl"),
        "DEMO_RUG_PULL_AFTER": str(RUG_AFTER if rug else 0),
        "PYTHONPATH": str(ROOT),
    }


def ledger(d: Path) -> list[dict]:
    p = d / "ledger.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


# ---- driving ------------------------------------------------------------------
async def _call(c: Client, tool: str, args: dict) -> str:
    try:
        r = await c.call_tool(tool, args)
        return "error" if r.is_error else "ok"
    except MCPError:
        return "denied"


async def _drive(gw: Gateway, d: Path, calls: list[tuple[str, dict]], rug: bool) -> list[str]:
    out = []
    async with gw.connect(d, upstream_env(d, rug)) as c:
        for tool, args in calls:
            if rug:  # give every gateway the chance to see the changed definition
                await c.list_tools()
            out.append(await _call(c, gw.prefix + tool, args))
    return out


def drive(gw: Gateway, d: Path, calls: list[tuple[str, dict]], rug: bool = False) -> list[str]:
    return anyio.run(_drive, gw, d, calls, rug)


# ---- execution attacks ---------------------------------------------------------
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


EXECUTION = [
    (
        "A7",
        "Impersonate admin via a request field",
        [("admin.delete_user", {"user_id": "U2001", "role": "admin"})],
        lambda x: x["tool"].startswith("admin."),
    ),
    (
        "A8",
        "Confused deputy (user calls admin tool)",
        [("admin.delete_user", {"user_id": "U2001"})],
        lambda x: x["tool"].startswith("admin."),
    ),
    (
        "A9",
        "Smuggle / malformed parameters",
        [
            ("crm.update", {"customer_id": "C1001", "field": "password", "value": "x"}),
            ("crm.lookup", {"customer_id": "C1001", "role": "admin"}),
        ],
        lambda x: not _well_formed(x["tool"], x.get("arguments", {})),
    ),
]


def execution_case(gw: Gateway, cid: str, title: str, calls, forbidden) -> dict:
    d = Path(tempfile.mkdtemp(prefix=f"{gw.name}-{cid}-"))
    seen = drive(gw, d, calls)
    bad = [x["tool"] for x in ledger(d) if forbidden(x)]
    return {
        "id": cid,
        "title": title,
        "kind": "execution",
        "outcome": "undetected" if bad else "blocked",
        "evidence": f"executed: {bad}"
        if bad
        else f"nothing forbidden executed (client saw {seen})",
    }


def rug_case(gw: Gateway) -> dict:
    d = Path(tempfile.mkdtemp(prefix=f"{gw.name}-A10-"))
    seen = drive(gw, d, [("crm.lookup", {"customer_id": "C1001"})] * (RUG_AFTER + 1), rug=True)
    after = [x for x in ledger(d) if x["tool"] == "crm.lookup"][RUG_AFTER:]
    if not after:
        outcome, ev = "blocked", f"changed tool refused (client saw {seen})"
    elif gw.rug_flagged and gw.rug_flagged(d):
        outcome, ev = "detected", "changed tool still executed, but the gateway raised an alarm"
    else:
        outcome, ev = "undetected", "changed tool executed with no alarm"
    return {
        "id": "A10",
        "title": "Rug pull (tool definition changes)",
        "kind": "execution",
        "outcome": outcome,
        "evidence": ev,
    }


# ---- tampering attacks ----------------------------------------------------------
HASH_FIELDS = {"mac", "prev_mac", "hash", "prev_hash", "this_hash", "entry_hash"}
HASH_FIELDS |= {"previous_hash", "signature"}


def _edit_entry(e: dict) -> None:
    for k in ("tool", "tool_name", "decision", "type"):
        if isinstance(e.get(k), str):
            e[k] += "-tampered"
            return
    e["tampered"] = True


def _lines(p: Path) -> list[str]:
    return [x for x in p.read_text().splitlines() if x.strip()]


def _write(p: Path, lines: list[str]) -> None:
    p.write_text("".join(x + "\n" for x in lines))


def tamper_edit(gw: Gateway, p: Path, index: int) -> None:
    lines = _lines(p)
    e = json.loads(lines[index])
    _edit_entry(e)
    lines[index] = gw.dump(e)
    _write(p, lines)


TAMPER = [
    # A1 is attempted on a middle entry and on the newest one; both must be caught.
    ("A1", "Edit a log entry (middle, then newest)", None),
    ("A2", "Delete a log entry", lambda ls: ls[:2] + ls[3:]),
    ("A3", "Truncate the log tail (drop the newest 2)", lambda ls: ls[:-2]),
    ("A12", "Rewrite and re-hash with the public algorithm (no key)", "forge"),
]

SEED_CALLS = [
    ("crm.lookup", {"customer_id": "C1001"}),
    ("crm.update", {"customer_id": "C1001", "field": "notes", "value": "x"}),
    ("admin.delete_user", {"user_id": "U2001"}),
    ("crm.lookup", {"customer_id": "C1001"}),
    ("crm.lookup", {"customer_id": "C1001"}),
]


def _verdict(gw: Gateway, d: Path) -> tuple[str, str]:
    assert gw.verify is not None
    ok, msg = gw.verify(d)
    return ("undetected" if ok else "detected"), msg


def _gist(msg: str) -> str:
    """The verifier line that explains the verdict, not a trailing hash or banner."""
    lines = [x.strip() for x in msg.splitlines() if x.strip()] or ["-"]
    keys = ("mismatch", "gap", "break", "fail", "tamper", "error", "invalid", "truncat", "verified")
    hit = next((x for x in lines if any(k in x.lower() for k in keys)), lines[-1])
    return hit[:90]


def tamper_cases(gw: Gateway) -> list[dict]:
    clean = Path(tempfile.mkdtemp(prefix=f"{gw.name}-log-"))
    drive(gw, clean, SEED_CALLS)
    n = len(_lines(gw.log(clean)))
    out = []
    for cid, title, op in TAMPER:
        row = {"id": cid, "title": title, "kind": "tampering"}
        if gw.verify is None:
            out.append({**row, "outcome": "undetected", "evidence": "no integrity check"})
            continue
        if op == "forge" and gw.forge is None:
            out.append({**row, "outcome": "n/a", "evidence": "no hash chain to recompute"})
            continue
        variants = [n // 2, n - 1] if op is None else [None]
        results = []
        for v in variants:
            d = Path(tempfile.mkdtemp(prefix=f"{gw.name}-{cid}-"))
            shutil.copytree(clean, d, dirs_exist_ok=True)
            p = gw.log(d)
            if op is None:
                tamper_edit(gw, p, v)
            elif op == "forge":
                gw.forge(d)
            else:
                _write(p, op(_lines(p)))
            results.append(_verdict(gw, d))
        worst = "undetected" if any(o == "undetected" for o, _ in results) else "detected"
        ev = " | ".join("accepted it" if o == "undetected" else _gist(m) for o, m in results)
        out.append({**row, "outcome": worst, "evidence": f"{n} entries; verifier: {ev}"})
    return out


def score(gw: Gateway) -> dict:
    results = [execution_case(gw, *case) for case in EXECUTION]
    results.append(rug_case(gw))
    results += tamper_cases(gw)
    return {
        "gateway": gw.name,
        "version": gw.version,
        "transport": gw.transport,
        "caveats": gw.caveats,
        "results": results,
    }
