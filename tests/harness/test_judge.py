"""Judging rules, tested on synthetic snapshots (no Docker needed)."""

from types import SimpleNamespace

from lab.attacks.scenarios import BY_ID, judge, unlogged_executions
from mcp_gateway.audit import VerifyReport
from mcp_gateway.audit.verify import Issue

OK = VerifyReport(entries=3)
BAD = VerifyReport(entries=3, issues=[Issue(2, 1, "mac_mismatch", "x")])


def snap(ledger=(), audit=(), verify=OK):
    return SimpleNamespace(ledger=list(ledger), audit=list(audit), verify=verify)


def req(seq, tool, args):
    return {"seq": seq, "type": "call_request", "payload": {"tool": tool, "args": args}}


def ex(tool, args):
    return {"tool": tool, "arguments": args}


LOOKUP = {"customer_id": "C1001"}
DELETE = {"user_id": "U2001"}


def test_unlogged_counts_duplicates():
    ledger = [ex("crm.lookup", LOOKUP)] * 2
    assert len(unlogged_executions(ledger, [req(1, "crm.lookup", LOOKUP)])) == 1


def test_tamper_outcomes():
    pre = snap(audit=[req(1, "crm.lookup", LOOKUP)])
    same = snap(ledger=[ex("crm.lookup", LOOKUP)], audit=pre.audit)
    edited = snap(ledger=[ex("crm.lookup", LOOKUP)], audit=[req(1, "crm.lookup", {"x": 1})])
    assert judge(BY_ID["A1"], pre, same)[0] == "blocked"
    assert judge(BY_ID["A1"], pre, snap(edited.ledger, edited.audit, BAD))[0] == "detected"
    assert judge(BY_ID["A1"], pre, edited)[0] == "undetected"


def test_spoofed_entry_counts_as_tamper():
    pre = snap(audit=[req(1, "crm.lookup", LOOKUP)])
    post = snap(
        ledger=[ex("crm.lookup", LOOKUP)],
        audit=[req(1, "crm.lookup", LOOKUP), req(2, "admin.delete_user", DELETE)],
    )
    assert judge(BY_ID["A11"], pre, post)[0] == "undetected"


def test_bypass_outcomes():
    pre = snap()
    assert judge(BY_ID["A6"], pre, snap(ledger=[]))[0] == "blocked"
    assert judge(BY_ID["A6"], pre, snap(ledger=[ex("admin.delete_user", DELETE)]))[0] == (
        "undetected"
    )


def test_forbidden_logged_is_detected_not_blocked():
    post = snap(
        ledger=[ex("admin.delete_user", DELETE)], audit=[req(1, "admin.delete_user", DELETE)]
    )
    assert judge(BY_ID["A8"], snap(), post)[0] == "detected"


def test_smuggled_parameters_are_forbidden():
    bad = ex("crm.update", {"customer_id": "C1001", "field": "password", "value": "x"})
    good = ex("crm.update", {"customer_id": "C1001", "field": "notes", "value": "x"})
    assert judge(BY_ID["A9"], snap(), snap(ledger=[good]))[0] == "blocked"
    assert judge(BY_ID["A9"], snap(), snap(ledger=[good, bad]))[0] == "undetected"


def test_rug_pull_threshold():
    calls = [ex("crm.lookup", LOOKUP)] * 3
    assert judge(BY_ID["A10"], snap(), snap(ledger=calls))[0] == "blocked"
    assert judge(BY_ID["A10"], snap(), snap(ledger=calls + calls[:1]))[0] == "undetected"
