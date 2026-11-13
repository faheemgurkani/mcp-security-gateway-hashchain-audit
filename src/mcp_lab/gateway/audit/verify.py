"""Standalone log verifier.

Checks, in order of what an attacker might try:
- ``bad_json``      line is not valid JSON
- ``mac_mismatch``  entry content was edited (or wrong key)
- ``seq_gap``       an entry was deleted or entries reordered
- ``broken_link``   ``prev_mac`` doesn't match the previous entry's mac
- ``truncated``     anchor head is beyond the end of the log, or disagrees with it
- ``time_gap``      no entry (not even a heartbeat) for longer than ``max_gap_ms``:
                    the gateway was likely stopped

Integrity only covers what was logged. Whether *everything* was logged is
an architectural property tested by the lab, not by this verifier.
"""

import json
import os
from dataclasses import dataclass, field

from mcp_lab.gateway.audit.anchor import Head
from mcp_lab.gateway.audit.chain import GENESIS_MAC, compute_mac


@dataclass(frozen=True)
class Issue:
    line: int
    seq: int | None
    kind: str
    detail: str


@dataclass
class VerifyReport:
    entries: int = 0
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def first_issue(self) -> Issue | None:
        return self.issues[0] if self.issues else None


def verify_log(
    path: str | os.PathLike[str],
    key: bytes,
    anchor_head: Head | None = None,
    max_gap_ms: int | None = None,
) -> VerifyReport:
    report = VerifyReport()
    expected_seq = 0
    prev_mac = GENESIS_MAC
    prev_ts: int | None = None
    last: dict | None = None

    with open(path, "rb") as f:
        lines = [ln for ln in f.read().split(b"\n") if ln.strip()]

    for lineno, raw in enumerate(lines, start=1):
        try:
            entry = json.loads(raw)
            seq = int(entry["seq"])
        except (ValueError, KeyError, TypeError) as e:
            report.issues.append(Issue(lineno, None, "bad_json", str(e)))
            continue
        report.entries += 1

        if compute_mac(key, entry) != entry.get("mac"):
            report.issues.append(Issue(lineno, seq, "mac_mismatch", "entry content altered"))
        if seq != expected_seq:
            report.issues.append(
                Issue(lineno, seq, "seq_gap", f"expected seq {expected_seq}, got {seq}")
            )
        if entry.get("prev_mac") != prev_mac:
            report.issues.append(
                Issue(lineno, seq, "broken_link", "prev_mac does not match previous entry")
            )
        ts = entry.get("ts_ms")
        if max_gap_ms is not None and prev_ts is not None and isinstance(ts, int):
            if ts - prev_ts > max_gap_ms:
                report.issues.append(
                    Issue(lineno, seq, "time_gap", f"{ts - prev_ts} ms since previous entry")
                )

        expected_seq = seq + 1
        prev_mac = entry.get("mac", "")
        prev_ts = ts if isinstance(ts, int) else prev_ts
        last = entry

    if anchor_head is not None:
        if last is None or anchor_head.seq > int(last["seq"]):
            have = -1 if last is None else int(last["seq"])
            report.issues.append(
                Issue(
                    len(lines),
                    have,
                    "truncated",
                    f"anchor head is seq {anchor_head.seq}, log ends at seq {have}",
                )
            )
        elif anchor_head.seq == int(last["seq"]) and anchor_head.mac != last.get("mac"):
            report.issues.append(
                Issue(len(lines), anchor_head.seq, "truncated", "anchor mac differs from log head")
            )

    return report
