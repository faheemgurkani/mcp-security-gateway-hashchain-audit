"""Smoke test for the mcp-gate external adapter; skipped unless the extra is installed."""

import pytest

mcpgate = pytest.importorskip("mcpgate", reason="install with: uv sync --extra external")


def test_mcpgate_policy_and_tamper(tmp_path, monkeypatch):
    from lab.adapters.mcpgate import score

    # confused deputy is blocked by mcp-gate's default-deny policy
    r = score.policy_case(
        "A8",
        "confused deputy",
        [("admin.delete_user", {"user_id": "U2001"})],
        lambda x: x["tool"].startswith("admin."),
    )
    assert r["execution"] == "blocked"

    # editing its audit file is caught by its own verifier
    r = score.tamper_case("A1", "edit", score._edit)
    assert r["tampering"] == "detected"
