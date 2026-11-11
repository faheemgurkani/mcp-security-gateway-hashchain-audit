"""The shared gateway harness, run against the reference gateway (and mcp-gate if installed)."""

import pytest

from lab.adapters import harness
from lab.adapters.gateways import REFERENCE


def test_reference_blocks_confused_deputy():
    r = harness.execution_case(REFERENCE, *harness.EXECUTION[1])  # A8
    assert r["outcome"] == "blocked"


def test_reference_blocks_rug_pull():
    assert harness.rug_case(REFERENCE)["outcome"] == "blocked"


def test_reference_detects_every_log_attack_without_the_key():
    results = {r["id"]: r["outcome"] for r in harness.tamper_cases(REFERENCE)}
    assert results == {"A1": "detected", "A2": "detected", "A3": "detected", "A12": "detected"}


def test_mcpgate_keyless_chain_accepts_a_rewrite():
    pytest.importorskip("mcpgate", reason="install with: uv sync --extra external")
    from lab.adapters.gateways import MCPGATE

    results = {r["id"]: r["outcome"] for r in harness.tamper_cases(MCPGATE())}
    assert results["A1"] == "detected" and results["A12"] == "undetected"
