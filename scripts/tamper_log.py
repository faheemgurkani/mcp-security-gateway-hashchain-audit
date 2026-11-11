"""Tamper with an audit log the way an attacker would, to see what the verifier catches.

    uv run python scripts/tamper_log.py MODE LOG [--seq N] [--key-file KEY --anchor HEAD]

Modes without the key (what an agent with write access but no key can do):
- ``edit``      change the payload of entry N                 -> mac_mismatch
- ``delete``    remove entry N                                -> seq_gap, broken_link
- ``truncate``  cut the log after entry N                     -> truncated (only with the anchor)
- ``spoof``     append a made-up entry with a guessed MAC     -> mac_mismatch, broken_link

Mode with the key (what an agent that can read the key can do, e.g. the colocated profile):
- ``forge``     edit entry N, then recompute every MAC from there on and rewrite the anchor.
                The verifier reports OK: the log is only as strong as the key's isolation.

The log is modified in place; work on a copy.
"""

import argparse
import json
from pathlib import Path

from mcp_gateway.audit.anchor import FileAnchor, Head
from mcp_gateway.audit.canonical import canonical
from mcp_gateway.audit.chain import GENESIS_MAC, compute_mac


def load(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_bytes().splitlines() if x.strip()]


def save(path: Path, entries: list[dict]) -> None:
    path.write_bytes(b"".join(canonical(e) + b"\n" for e in entries))


def edit_payload(entry: dict) -> None:
    entry["payload"] = {**entry["payload"], "tampered": True}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["edit", "delete", "truncate", "spoof", "forge"])
    ap.add_argument("log", type=Path)
    ap.add_argument("--seq", type=int, default=1, help="entry to target (default 1)")
    ap.add_argument("--key-file", type=Path, help="HMAC key (forge only)")
    ap.add_argument("--anchor", type=Path, help="anchor to rewrite (forge only)")
    a = ap.parse_args()

    entries = load(a.log)
    if not 0 <= a.seq < len(entries):
        ap.error(f"--seq must be between 0 and {len(entries) - 1}")

    if a.mode == "edit":
        edit_payload(entries[a.seq])
    elif a.mode == "delete":
        del entries[a.seq]
    elif a.mode == "truncate":
        entries = entries[: a.seq + 1]
    elif a.mode == "spoof":
        last = entries[-1]
        entries.append(
            {
                **last,
                "seq": last["seq"] + 1,
                "type": "call_request",
                "payload": {"tool": "crm.lookup", "args": {"customer_id": "C1001"}},
                "prev_mac": "f" * 64,
                "mac": "e" * 64,
            }
        )
    elif a.mode == "forge":
        if a.key_file is None:
            ap.error("forge needs --key-file")
        key = bytes.fromhex(a.key_file.read_text().strip())
        edit_payload(entries[a.seq])
        prev = GENESIS_MAC if a.seq == 0 else entries[a.seq - 1]["mac"]
        for e in entries[a.seq :]:
            e["prev_mac"] = prev
            e["mac"] = compute_mac(key, e)
            prev = e["mac"]
        if a.anchor is not None:
            FileAnchor(a.anchor).write(Head(seq=entries[-1]["seq"], mac=entries[-1]["mac"]))

    save(a.log, entries)
    print(f"{a.mode}: {a.log} now has {len(entries)} entries")


if __name__ == "__main__":
    main()
