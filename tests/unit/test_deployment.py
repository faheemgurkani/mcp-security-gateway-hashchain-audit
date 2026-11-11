"""check-deployment maps what the agent's user can touch to the lab's profiles."""

import os
import socket

import pytest

from mcp_lab.deployment import as_text, check_deployment

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root can read and write anything")


@pytest.fixture
def files(tmp_path):
    gw = tmp_path / "gateway"
    gw.mkdir()
    paths = {n: gw / n for n in ("audit.key", "audit.jsonl", "head.json")}
    for p in paths.values():
        p.write_text("x")
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}")
    return gw, paths, cfg


def _lock(gw, paths):
    for p in paths.values():
        p.chmod(0o000)
    gw.chmod(0o500)


def test_isolated_is_reference(files):
    gw, paths, _ = files
    _lock(gw, paths)
    try:
        r = check_deployment(paths["audit.key"], paths["audit.jsonl"], paths["head.json"])
        assert r.profile == "reference" and r.loses == []
    finally:
        gw.chmod(0o700)


def test_writable_log_without_key_is_breach(files):
    gw, paths, _ = files
    paths["audit.key"].chmod(0o000)
    paths["head.json"].chmod(0o400)
    gw.chmod(0o500)
    try:
        r = check_deployment(paths["audit.key"], paths["audit.jsonl"], paths["head.json"])
        assert r.profile == "breach"
        assert any("detected, not prevented" in x for x in r.loses)
    finally:
        gw.chmod(0o700)


def test_readable_key_is_colocated(files):
    _, paths, cfg = files
    r = check_deployment(paths["audit.key"], paths["audit.jsonl"], paths["head.json"], cfg)
    assert r.profile == "colocated"
    assert "A12 rewrite" in as_text(r) and "A4 remove the gateway" in as_text(r)


def test_reachable_tool_server_with_credential_opens_bypass(files):
    gw, paths, _ = files
    _lock(gw, paths)
    cred = gw.parent / "upstream_token"
    cred.write_text("t")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        url = f"http://127.0.0.1:{s.getsockname()[1]}/mcp"
        try:
            r = check_deployment(paths["audit.key"], secrets=[cred], tool_urls=[url])
        finally:
            gw.chmod(0o700)
    assert r.profile == "breach"
    assert any("around the gateway" in x for x in r.loses)


def test_nothing_given_is_unknown():
    assert check_deployment().profile == "unknown"
