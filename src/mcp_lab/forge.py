"""Recognise keyless hash chains, and forge them (A12) without gateway-specific code.

A *keyless* chain computes each entry's hash from public data only, so whoever can
write the log can edit an entry and recompute every hash after it. This module
tries a catalogue of the schemes seen in published gateways:

- a hash field (``hash``, ``entry_hash``, ``this_hash``, ...) over the entry minus
  that field, with or without the previous hash prepended, under several JSON
  serializations (RFC 8785, sorted compact, sorted with spaces, insertion order);
- a ``prev_hash``-style field that holds the SHA-256 of the previous raw line.

A scheme is used only if it **reproduces every hash in the untouched log**, so a
match is itself evidence: this log can be recomputed without any secret. Forging
then edits one entry, recomputes the chain from there, and rewrites any other file
in the gateway's directory that held an old head hash (a sidecar or anchor the
attacker can also write). The gateway's own verifier decides the outcome; a scheme
we get wrong yields a log it rejects, which can only flatter the gateway.
"""

import hashlib
import json
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import rfc8785

HASH_FIELDS = ["hash", "entry_hash", "this_hash", "record_hash", "event_hash", "chain_hash",
               "current_hash", "curr_hash", "digest"]  # fmt: skip
PREV_FIELDS = ["prev_hash", "previous_hash", "prev", "parent_hash", "prev_digest"]
KEYED_FIELDS = ["mac", "hmac", "prev_mac", "signature", "sig", "signed", "signature_b64"]
EDIT_FIELDS = ["tool", "tool_name", "decision", "type", "event", "action", "kind", "method"]


def _nfc(o: object) -> object:
    if isinstance(o, str):
        return unicodedata.normalize("NFC", o)
    if isinstance(o, dict):
        return {_nfc(k): _nfc(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_nfc(v) for v in o]
    return o


SERIALIZERS: dict[str, Callable[[dict], bytes]] = {
    "rfc8785": lambda e: rfc8785.dumps(e),
    "sorted-compact": lambda e: json.dumps(e, sort_keys=True, separators=(",", ":")).encode(),
    "sorted-compact-utf8": lambda e: json.dumps(
        _nfc(e), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode(),
    "sorted-spaced": lambda e: json.dumps(e, sort_keys=True).encode(),
    "insertion-compact": lambda e: json.dumps(e, separators=(",", ":")).encode(),
    "insertion-spaced": lambda e: json.dumps(e).encode(),
}
LINE_STYLES: dict[str, Callable[[dict], str]] = {
    "rfc8785": lambda e: rfc8785.dumps(e).decode(),
    "sorted-compact": lambda e: json.dumps(e, sort_keys=True, separators=(",", ":")),
    "sorted-spaced-utf8": lambda e: json.dumps(e, sort_keys=True, ensure_ascii=False),
    "sorted-spaced": lambda e: json.dumps(e, sort_keys=True),
    "insertion-compact": lambda e: json.dumps(e, separators=(",", ":")),
    "insertion-spaced": lambda e: json.dumps(e),
    "insertion-spaced-utf8": lambda e: json.dumps(e, ensure_ascii=False),
}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_entries(path: Path) -> tuple[list[str], list[dict]]:
    lines = [x for x in path.read_text().splitlines() if x.strip()]
    return lines, [json.loads(x) for x in lines]


def line_style(lines: list[str], entries: list[dict]) -> Callable[[dict], str]:
    """The serializer that reproduces the log's own lines, so edits look native."""
    for fn in LINE_STYLES.values():
        if all(fn(e) == x for e, x in zip(entries, lines, strict=True)):
            return fn
    return LINE_STYLES["insertion-compact"]


@dataclass
class Scheme:
    """One way of computing a chain. ``recompute`` rewrites entries[start:] in place."""

    name: str
    recompute: Callable[[list[dict], int, list[str]], None]


def _prefix(value: str) -> str:
    return value.split(":", 1)[0] + ":" if ":" in value else ""


def _field_schemes(hf: str, pf: str | None) -> list[Scheme]:
    out = []
    for sname, ser in SERIALIZERS.items():
        for prepend in (False, True):
            for drop_prev in (False, True) if pf else (False,):

                def recompute(es, start, _lines, ser=ser, prepend=prepend, drop_prev=drop_prev):
                    pre = _prefix(str(es[0].get(hf, "")))
                    prev = es[start - 1][hf] if start else (es[0].get(pf) if pf else None)
                    for e in es[start:]:
                        if pf:
                            e[pf] = prev
                        body = {
                            k: v for k, v in e.items() if k != hf and not (drop_prev and k == pf)
                        }
                        raw = ser(body)
                        bare = (prev or "").split(":", 1)[-1] if pre else (prev or "")
                        digest = _sha(bare.encode() + raw) if prepend else _sha(raw)
                        e[hf] = prev = pre + digest

                label = f"sha256({'prev + ' if prepend else ''}{sname}(entry - {hf}"
                label += f" - {pf}))" if drop_prev else "))"
                out.append(Scheme(f"{hf}/{pf or '-'}: {label}", recompute))
    return out


def _prev_line_scheme(pf: str) -> Scheme:
    def recompute(es, start, lines):
        # hash previous lines exactly as the log writes them (style from the original lines)
        style = line_style(lines, [json.loads(x) for x in lines])
        pre = _prefix(str(es[1].get(pf, ""))) if len(es) > 1 else ""
        for i in range(max(start, 1), len(es)):
            es[i][pf] = pre + _sha(style(es[i - 1]).encode())

    return Scheme(f"{pf}: sha256(previous line)", recompute)


def candidate_schemes(entries: list[dict]) -> list[Scheme]:
    keys = set.intersection(*(set(e) for e in entries)) if entries else set()
    hfs = [f for f in HASH_FIELDS if f in keys]
    pfs = [f for f in PREV_FIELDS if f in keys] or [None]
    out = [s for hf in hfs for pf in pfs for s in _field_schemes(hf, pf)]
    out += [_prev_line_scheme(pf) for pf in pfs if pf]
    return out


def matching_schemes(lines: list[str], entries: list[dict]) -> list[Scheme]:
    """Schemes that reproduce the untouched log exactly: the chain needs no secret."""
    out = []
    for s in candidate_schemes(entries):
        trial = json.loads(json.dumps(entries))
        try:
            s.recompute(trial, 0, lines)
        except (TypeError, KeyError, ValueError):
            continue
        if trial == entries:
            out.append(s)
    return out


def keyed_fields(entries: list[dict]) -> list[str]:
    keys = set().union(*(set(e) for e in entries)) if entries else set()
    return [f for f in KEYED_FIELDS if f in keys]


def _edit(e: dict) -> None:
    for k in EDIT_FIELDS:
        if isinstance(e.get(k), str):
            e[k] += "-tampered"
            return
    e["tampered"] = True


def forge(log: Path, scheme: Scheme, workdir: Path) -> None:
    """Edit the middle entry, recompute the chain, and move any head copies along."""
    lines, entries = read_entries(log)
    style = line_style(lines, entries)
    old = json.loads(json.dumps(entries))
    i = len(entries) // 2
    _edit(entries[i])
    scheme.recompute(entries, i, lines)
    new_lines = [style(e) for e in entries]
    log.write_text("".join(x + "\n" for x in new_lines))
    # Head copies: any small file in the gateway's directory naming an old hash value
    # (or the old last line's digest) is rewritten to the new one.
    swaps = {_sha(lines[-1].encode()): _sha(new_lines[-1].encode())}
    for a, b in zip(old, entries, strict=True):
        for k in set(a) & set(b):
            if isinstance(a[k], str) and a[k] != b[k] and len(a[k]) >= 32:
                swaps[a[k]] = b[k]
    for f in workdir.rglob("*"):
        if f == log or not f.is_file() or f.stat().st_size > 1_000_000:
            continue
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        new = text
        for a, b in swaps.items():
            new = new.replace(a, b)
        if new != text:
            f.write_text(new)
