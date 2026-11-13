from mcp_lab.gateway.identity import (
    Principal,
    SessionRegistry,
    find_impersonation_fields,
    hash_token,
)

REG = SessionRegistry({hash_token("tok-user"): Principal("alice", "user")})


def test_resolve_known_token():
    assert REG.resolve("tok-user") == Principal("alice", "user")


def test_unknown_or_missing_token():
    assert REG.resolve("forged") is None
    assert REG.resolve(None) is None
    assert REG.resolve("") is None


def test_registry_never_stores_plain_tokens():
    assert "tok-user" not in REG._by_hash


def test_impersonation_fields_found_case_insensitive():  # A7
    assert find_impersonation_fields({"customer_id": "C1", "Role": "admin", "as_user": "x"}) == [
        "Role",
        "as_user",
    ]
    assert find_impersonation_fields(None) == []
