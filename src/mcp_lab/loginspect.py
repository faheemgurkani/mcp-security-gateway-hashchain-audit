"""What does an agent's audit log actually prove? (``mcp-lab inspect-log``)

For someone handed a log as evidence: is it chained, can the chain be recomputed
without a secret, is anything keyed or signed, and is the head kept anywhere else?
Purely offline and read-only.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcp_lab import forge


@dataclass
class LogReport:
    path: str
    entries: int
    fields: list[str]
    keyless_schemes: list[str] = field(default_factory=list)
    keyed_fields: list[str] = field(default_factory=list)
    head_copies: list[str] = field(default_factory=list)
    verdict: str = ""
    questions: list[str] = field(default_factory=list)


def inspect_log(path: Path) -> LogReport:
    lines, entries = forge.read_entries(path)
    keys = sorted(set().union(*(set(e) for e in entries))) if entries else []
    r = LogReport(str(path), len(entries), keys)
    r.keyless_schemes = [s.name for s in forge.matching_schemes(lines, entries)]
    r.keyed_fields = forge.keyed_fields(entries)
    if entries:
        last = [str(v) for v in entries[-1].values() if isinstance(v, str) and len(v) >= 32]
        for f in sorted(path.parent.iterdir()):
            if f == path or not f.is_file() or f.stat().st_size > 1_000_000:
                continue
            try:
                text = f.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if any(v in text for v in last):
                r.head_copies.append(f.name)

    if r.keyless_schemes:
        r.verdict = (
            "Keyless hash chain: every hash is reproducible from public data "
            f"({r.keyless_schemes[0]}). It proves the log is internally consistent, not "
            "that it is unaltered: anyone who can write this file can edit an entry and "
            "recompute the chain (attack A12)."
        )
    elif r.keyed_fields:
        r.verdict = (
            f"Keyed or signed fields present ({', '.join(r.keyed_fields)}) and no public "
            "scheme reproduces the chain. Its strength depends entirely on where the key is "
            "and on whether the verifier really checks it."
        )
    else:
        r.verdict = (
            "No hash chain recognised: a plain log. Edits, deletions and truncation cannot "
            "be detected from the log itself."
        )
    r.questions = [
        "Who could write this file while the agent ran? If the agent's own OS user could, "
        "treat the log as the agent's account of events, not as evidence.",
        "If keyed: where was the key, and could the agent (or its user) read it?",
        "If signed: does the verifier check the signatures, with a public key the writer "
        "doesn't control? Run it on a deliberately edited copy to see.",
        "Where is the head (last hash and sequence number) recorded? A copy next to the log "
        "moves with it; only an off-host or write-protected copy catches truncation.",
        "Are there heartbeats or sequence numbers, so a gap (gateway killed, entries "
        "dropped) is visible?",
    ]
    if r.head_copies:
        r.questions.insert(
            3,
            f"A head copy sits in the same directory ({', '.join(r.head_copies)}): whoever "
            "can rewrite the log can probably rewrite it too.",
        )
    return r


def as_text(r: LogReport) -> str:
    out = [f"{r.path}: {r.entries} entries", f"fields: {', '.join(r.fields)}", "", r.verdict]
    out += ["", "Questions to ask before relying on it:"]
    out += [f"  {i}. {q}" for i, q in enumerate(r.questions, 1)]
    return "\n".join(out)


def as_json(r: LogReport) -> str:
    return json.dumps(r.__dict__, indent=2)
