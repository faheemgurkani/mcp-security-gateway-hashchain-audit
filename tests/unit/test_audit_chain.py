import json

import pytest

from mcp_lab.gateway.audit import AuditChain, AuditWriteError, FileAnchor, verify_log
from mcp_lab.gateway.audit.canonical import canonical

KEY = b"k" * 32


@pytest.fixture
def log(tmp_path):
    anchor = FileAnchor(tmp_path / "head.json")
    chain = AuditChain(tmp_path / "audit.jsonl", KEY, anchor)
    for i in range(5):
        chain.append("tool_call", {"tool": "crm.lookup", "i": i}, session="s1")
    return chain.path, anchor


def _lines(path):
    return path.read_bytes().splitlines()


def _write(path, lines):
    path.write_bytes(b"\n".join(lines) + b"\n")


def test_canonical_is_order_independent():
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1}) == b'{"a":2,"b":1}'


def test_clean_log_verifies(log):
    path, anchor = log
    report = verify_log(path, KEY, anchor.read())
    assert report.ok and report.entries == 5


def test_edit_detected_at_exact_seq(log):  # A1
    path, anchor = log
    lines = _lines(path)
    e = json.loads(lines[2])
    e["payload"]["tool"] = "admin.delete_user"
    lines[2] = json.dumps(e).encode()
    _write(path, lines)
    report = verify_log(path, KEY, anchor.read())
    assert report.first_issue.kind == "mac_mismatch" and report.first_issue.seq == 2


def test_delete_middle_detected(log):  # A2
    path, anchor = log
    lines = _lines(path)
    del lines[2]
    _write(path, lines)
    kinds = {i.kind for i in verify_log(path, KEY, anchor.read()).issues}
    assert {"seq_gap", "broken_link"} <= kinds


def test_reorder_detected(log):
    path, anchor = log
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write(path, lines)
    assert not verify_log(path, KEY, anchor.read()).ok


def test_truncation_only_caught_by_anchor(log):  # A3
    path, anchor = log
    _write(path, _lines(path)[:3])
    assert verify_log(path, KEY).ok  # chain alone can't see a clean cut
    report = verify_log(path, KEY, anchor.read())
    assert report.first_issue.kind == "truncated"


def test_recomputing_chain_without_key_fails(log):  # A11: forge entries with a guessed key
    path, anchor = log
    forger = AuditChain(path.with_name("forged.jsonl"), b"x" * 32)
    for i in range(5):
        forger.append("tool_call", {"tool": "crm.lookup", "i": i}, session="s1")
    assert not verify_log(forger.path, KEY).ok


def test_time_gap_detected(tmp_path, monkeypatch):  # A5: gateway silent for 60 s
    import mcp_lab.gateway.audit.chain as mod

    chain = AuditChain(tmp_path / "gap.jsonl", KEY)
    chain.append("heartbeat", {"n": 1})
    chain.append("heartbeat", {"n": 2})
    assert verify_log(chain.path, KEY, max_gap_ms=10_000).ok

    real = mod.time.time_ns
    monkeypatch.setattr(mod.time, "time_ns", lambda: real() + 60_000 * 1_000_000)
    chain.append("heartbeat", {"n": 3})
    assert verify_log(chain.path, KEY, max_gap_ms=10_000).first_issue.kind == "time_gap"


def test_resume_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditChain(p, KEY).append("proxy_start", {})
    c2 = AuditChain(p, KEY)
    c2.append("proxy_start", {})
    assert c2.head.seq == 1 and verify_log(p, KEY).ok


def test_unwritable_log_fails_closed(tmp_path):
    chain = AuditChain(tmp_path / "missing_dir" / "a.jsonl", KEY)
    with pytest.raises(AuditWriteError):
        chain.append("tool_call", {})


def test_short_key_rejected(tmp_path):
    with pytest.raises(ValueError):
        AuditChain(tmp_path / "a.jsonl", b"short")
