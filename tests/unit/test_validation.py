from pathlib import Path

import pytest

from mcp_lab.gateway.validation import ArgumentError, ArgumentRules, close_schema, load_rules_file

DEMO_RULES = Path(__file__).resolve().parents[2] / "src/mcp_lab/demo/arg-rules.yaml"


@pytest.fixture
def demo() -> ArgumentRules:
    return ArgumentRules.build(load_rules_file(DEMO_RULES), None)


def test_valid_args(demo):
    assert demo.validate("crm.lookup", {"customer_id": "C1234"}) == {"customer_id": "C1234"}


@pytest.mark.parametrize(
    "tool,args",
    [
        ("crm.lookup", {"customer_id": "C1234", "role": "admin"}),  # smuggled field (A7/A9)
        ("crm.lookup", {"customer_id": "1234; DROP TABLE"}),  # pattern
        ("crm.lookup", {"customer_id": 1234}),  # strict type, no coercion
        ("crm.lookup", {}),  # missing
        ("crm.lookup", None),
        ("crm.update", {"customer_id": "C1234", "field": "password", "value": "x"}),
        ("crm.update", {"customer_id": "C1234", "field": "notes", "value": "x" * 501}),
        ("unknown.tool", {}),  # no rule -> deny
    ],
)
def test_invalid_args_rejected(demo, tool, args):
    with pytest.raises(ArgumentError):
        demo.validate(tool, args)


# ---- any tool: rules from the tool's own (pinned) schema ----------------------------------
TICKET = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "priority": {"type": "integer", "minimum": 1, "maximum": 5},
        "labels": {"type": "array", "items": {"type": "object", "properties": {"k": {}}}},
    },
    "required": ["title"],
}


def test_upstream_schema_is_used_and_closed():
    rules = ArgumentRules.build(None, {"tickets.create": TICKET})
    assert rules.sources == {"tickets.create": "upstream"}
    assert rules.validate("tickets.create", {"title": "x", "priority": 2}) == {
        "title": "x",
        "priority": 2,
    }
    for bad in (
        {"title": "x", "assignee": "root"},  # undeclared field
        {"title": "x", "priority": "2"},  # no coercion
        {"title": "x", "priority": 9},  # range
        {"title": "x", "labels": [{"k": 1, "smuggled": 2}]},  # closed at depth too
        {"priority": 1},  # required
    ):
        with pytest.raises(ArgumentError):
            rules.validate("tickets.create", bad)


def test_config_overrides_upstream():
    tight = {"type": "object", "properties": {"title": {"type": "string", "maxLength": 3}}}
    rules = ArgumentRules.build({"tickets.create": tight}, {"tickets.create": TICKET})
    assert rules.sources == {"tickets.create": "config"}
    with pytest.raises(ArgumentError):
        rules.validate("tickets.create", {"title": "too long"})


def test_explicitly_open_schema_stays_open():
    s = close_schema({"type": "object", "additionalProperties": True})
    assert s["additionalProperties"] is True
    rules = ArgumentRules.build(
        None, {"free.form": {"type": "object", "additionalProperties": True}}
    )
    assert rules.validate("free.form", {"anything": 1}) == {"anything": 1}


def test_tool_without_schema_is_denied():
    rules = ArgumentRules.build(None, {"no.schema": {}})
    with pytest.raises(ArgumentError):
        rules.validate("no.schema", {})


def test_invalid_schema_fails_at_startup():
    with pytest.raises(ValueError):
        ArgumentRules.build({"bad": {"type": "not-a-type"}}, None)


def test_rules_hash_changes_with_rules():
    a = ArgumentRules.build(None, {"t": TICKET})
    b = ArgumentRules.build({"t": {"type": "object"}}, {"t": TICKET})
    assert a.sha256 != b.sha256
