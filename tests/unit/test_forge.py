"""The generic A12 forger recognises the keyless schemes seen in published gateways."""

import hashlib
import json
import unicodedata
from pathlib import Path

import pytest
import rfc8785

from mcp_lab import forge
from mcp_lab.loginspect import inspect_log


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sorted_compact(e: dict) -> bytes:
    return json.dumps(e, sort_keys=True, separators=(",", ":")).encode()


# Each scheme: (write a chained log, verify it) as the gateway itself would.
def write_hash_over_entry(p: Path, recs: list[dict]) -> None:  # mcp-gate-policy style
    prev, out = "0" * 64, []
    for r in recs:
        e = {**r, "prev_hash": prev}
        e["hash"] = prev = sha(sorted_compact(e))
        out.append(json.dumps(e, sort_keys=True, separators=(",", ":")))
    p.write_text("\n".join(out) + "\n")


def verify_hash_over_entry(p: Path) -> bool:
    prev = "0" * 64
    for line in p.read_text().splitlines():
        e = json.loads(line)
        body = {k: v for k, v in e.items() if k != "hash"}
        if e["prev_hash"] != prev or e["hash"] != sha(sorted_compact(body)):
            return False
        prev = e["hash"]
    return True


def nfc_canon(e: dict) -> bytes:
    n = {k: unicodedata.normalize("NFC", v) if isinstance(v, str) else v for k, v in e.items()}
    return json.dumps(n, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_prev_prepended(p: Path, recs: list[dict]) -> None:  # shugo style
    prev, out = "0" * 64, []
    for r in recs:
        e = {**r, "prev_hash": prev}
        e["this_hash"] = prev = sha(prev.encode() + nfc_canon(e))
        out.append(json.dumps(e, sort_keys=True, ensure_ascii=False))
    p.write_text("\n".join(out) + "\n")


def verify_prev_prepended(p: Path) -> bool:
    prev = "0" * 64
    for line in p.read_text().splitlines():
        e = json.loads(line)
        body = {k: v for k, v in e.items() if k != "this_hash"}
        if e["prev_hash"] != prev or e["this_hash"] != sha(prev.encode() + nfc_canon(body)):
            return False
        prev = e["this_hash"]
    return True


def write_jcs_with_head(p: Path, recs: list[dict]) -> None:  # glp style, .head sidecar
    prev, out = "0" * 64, []
    for i, r in enumerate(recs, 1):
        e = {**r, "seq": i, "prev_hash": prev}
        e["entry_hash"] = prev = sha(rfc8785.dumps(e))
        out.append(rfc8785.dumps(e).decode())
    p.write_text("\n".join(out) + "\n")
    (p.parent / (p.name + ".head")).write_text(json.dumps({"entry_hash": prev, "seq": len(out)}))


def verify_jcs_with_head(p: Path) -> bool:
    prev, last = "0" * 64, None
    for line in p.read_text().splitlines():
        e = json.loads(line)
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if e["prev_hash"] != prev or e["entry_hash"] != sha(rfc8785.dumps(body)):
            return False
        prev, last = e["entry_hash"], e
    head = json.loads((p.parent / (p.name + ".head")).read_text())
    return head == {"entry_hash": last["entry_hash"], "seq": last["seq"]}


def write_prev_line(p: Path, recs: list[dict]) -> None:  # hash of the previous raw line
    out, prev_line = [], None
    for r in recs:
        e = {**r, "previous_hash": sha(prev_line.encode()) if prev_line else None}
        prev_line = json.dumps(e, separators=(",", ":"))
        out.append(prev_line)
    p.write_text("\n".join(out) + "\n")


def verify_prev_line(p: Path) -> bool:
    lines = p.read_text().splitlines()
    return all(
        json.loads(lines[i])["previous_hash"] == sha(lines[i - 1].encode())
        for i in range(1, len(lines))
    )


RECS = [{"tool": f"crm.lookup.{i}", "decision": "allow"} for i in range(6)]
SCHEMES = [
    (write_hash_over_entry, verify_hash_over_entry),
    (write_prev_prepended, verify_prev_prepended),
    (write_jcs_with_head, verify_jcs_with_head),
    (write_prev_line, verify_prev_line),
]


@pytest.mark.parametrize("write,verify", SCHEMES, ids=lambda f: getattr(f, "__name__", ""))
def test_scheme_is_recognised_and_forged(tmp_path, write, verify):
    log = tmp_path / "audit.jsonl"
    write(log, RECS)
    assert verify(log)
    lines, entries = forge.read_entries(log)
    schemes = forge.matching_schemes(lines, entries)
    assert schemes, "a keyless scheme should reproduce the log"
    before = log.read_text()
    forge.forge(log, schemes[0], tmp_path)
    assert log.read_text() != before and "-tampered" in log.read_text()
    assert verify(log), "the forged log passes the gateway's own check"


def test_naive_edit_is_caught_by_the_same_verifiers(tmp_path):
    for write, verify in SCHEMES:
        log = tmp_path / f"{write.__name__}.jsonl"
        write(log, RECS)
        lines = log.read_text().splitlines()
        lines[2] = lines[2].replace("crm.lookup.2", "crm.lookup.X")
        log.write_text("\n".join(lines) + "\n")
        assert not verify(log), write.__name__


def test_keyed_chain_is_not_recomputable(tmp_path):
    import hmac

    log, key, prev, out = tmp_path / "audit.jsonl", b"secret", "0" * 64, []
    for r in RECS:
        e = {**r, "prev_mac": prev}
        e["mac"] = prev = hmac.new(key, sorted_compact(e), "sha256").hexdigest()
        out.append(json.dumps(e, sort_keys=True, separators=(",", ":")))
    log.write_text("\n".join(out) + "\n")
    lines, entries = forge.read_entries(log)
    assert forge.matching_schemes(lines, entries) == []
    assert forge.keyed_fields(entries) == ["mac", "prev_mac"]
    assert "Keyed or signed" in inspect_log(log).verdict


def test_inspect_log_explains_keyless_and_plain_logs(tmp_path):
    keyless = tmp_path / "a" / "audit.jsonl"
    keyless.parent.mkdir()
    write_jcs_with_head(keyless, RECS)
    r = inspect_log(keyless)
    assert r.keyless_schemes and "A12" in r.verdict
    assert r.head_copies == ["audit.jsonl.head"]
    plain = tmp_path / "plain.jsonl"
    plain.write_text("\n".join(json.dumps(x) for x in RECS) + "\n")
    assert "No hash chain" in inspect_log(plain).verdict
