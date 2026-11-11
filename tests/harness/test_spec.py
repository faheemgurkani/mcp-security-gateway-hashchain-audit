"""`mcp-lab score` end to end on example specs, with no third-party gateway installed."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_lab.cli import app
from mcp_lab.spec import Spec, SpecError

ROOT = Path(__file__).resolve().parents[2]
SPECS = ROOT / "examples/specs"
TOY_EXPECTED = {
    "A7": "blocked",
    "A8": "blocked",
    "A9": "undetected",  # no argument checks
    "A10": "undetected",  # no pinning
    "A1": "detected",
    "A2": "detected",
    "A3": "undetected",  # head not kept anywhere else
    "A12": "undetected",  # keyless chain: recomputed and accepted
}


def _outcomes(path: Path) -> dict[str, dict[str, str]]:
    data = json.loads(path.read_text())
    return {g["gateway"]: {r["id"]: r["outcome"] for r in g["results"]} for g in data["gateways"]}


def test_score_toy_and_reference_specs(tmp_path):
    out = tmp_path / "r.json"
    md = tmp_path / "r.md"
    res = CliRunner().invoke(
        app,
        ["score", str(SPECS / "toy-gateway.yaml"), str(SPECS / "reference.yaml"),
         "--json", str(out), "--markdown", str(md)],
    )  # fmt: skip
    assert res.exit_code == 1, res.output  # the toy has undetected attacks: CI gate trips
    got = _outcomes(out)
    assert got["toy-gateway"] == TOY_EXPECTED
    ref = got["reference-gateway"]
    assert all(ref[i] == "blocked" for i in ("A7", "A8", "A9", "A10"))
    assert all(ref[i] == "detected" for i in ("A1", "A2", "A3"))
    assert ref["A12"] == "n/a"  # keyed chain: nothing public to recompute
    assert "❌ undetected" in md.read_text()


def test_fail_on_never_exits_zero(tmp_path):
    res = CliRunner().invoke(app, ["score", str(SPECS / "toy-gateway.yaml"), "--fail-on", "never"])
    assert res.exit_code == 0, res.output


def test_every_example_spec_and_the_template_parse():
    for p in SPECS.glob("*.yaml"):
        Spec.load(p)
    Spec.load(ROOT / "src/mcp_lab/template.yaml")


def test_spec_errors_are_reported(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\ncommand: y\nverify: z\n")
    with pytest.raises(SpecError, match="needs 'log'"):
        Spec.load(bad)
    bad.write_text("name: x\ncommand: y\ntypo_key: 1\n")
    with pytest.raises(SpecError, match="unknown keys"):
        Spec.load(bad)


def test_broken_gateway_gives_a_clear_error(tmp_path):
    spec = tmp_path / "broken.yaml"
    spec.write_text("name: broken\ncommand: exit 3\n")
    res = CliRunner().invoke(app, ["score", str(spec)])
    assert res.exit_code == 2 and "could not talk MCP" in res.output
