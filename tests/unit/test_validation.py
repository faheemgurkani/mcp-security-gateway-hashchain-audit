import pytest

from mcp_gateway.validation import ArgumentError, validate_arguments


def test_valid_args():
    assert validate_arguments("crm.lookup", {"customer_id": "C1234"}) == {"customer_id": "C1234"}


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
        ("unknown.tool", {}),  # no schema -> deny
    ],
)
def test_invalid_args_rejected(tool, args):
    with pytest.raises(ArgumentError):
        validate_arguments(tool, args)
