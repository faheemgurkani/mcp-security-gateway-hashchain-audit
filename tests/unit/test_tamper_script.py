import subprocess
import sys
from pathlib import Path

import pytest

from mcp_gateway.audit import AuditChain, FileAnchor, verify_log

ROOT = Path(__file__).resolve().parents[2]
KEY = b"k" * 32


@pytest.fixture
def log(tmp_path):
    anchor = FileAnchor(tmp_path / "head.json")
    chain = AuditChain(tmp_path / "audit.jsonl", KEY, anchor)
    for i in range(5):
        chain.append("call_request", {"tool": "crm.lookup", "i": i}, session="s1")
    (tmp_path / "key").write_text(KEY.hex())
    return tmp_path


def tamper(*args: str) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/tamper_log.py"), *args], check=True, cwd=ROOT
    )


@pytest.mark.parametrize(
    "mode,kind",
    [
        ("edit", "mac_mismatch"),
        ("delete", "seq_gap"),
        ("truncate", "truncated"),
        ("spoof", "broken_link"),
    ],
)
def test_keyless_tampering_is_detected(log, mode, kind):
    tamper(mode, str(log / "audit.jsonl"), "--seq", "2")
    report = verify_log(log / "audit.jsonl", KEY, FileAnchor(log / "head.json").read())
    assert kind in {i.kind for i in report.issues}


def test_forge_with_key_passes_verification(log):
    tamper(
        "forge",
        str(log / "audit.jsonl"),
        "--seq",
        "2",
        "--key-file",
        str(log / "key"),
        "--anchor",
        str(log / "head.json"),
    )
    report = verify_log(log / "audit.jsonl", KEY, FileAnchor(log / "head.json").read())
    assert report.ok  # the key-holding attacker wins: why isolation matters
