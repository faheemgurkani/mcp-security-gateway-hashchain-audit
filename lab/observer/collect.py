"""Observer: ground truth gathered from outside every zone (the host).

It never goes through the agent and never trusts the gateway's own claims:
- the tool zone's execution ledger: what *actually* ran
- the gateway's audit log + anchor, copied out with `docker compose cp`
  (works even if the gateway container was stopped or killed)
- Docker events: container kills, stops and restarts during the run
"""

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from mcp_gateway.audit import FileAnchor, VerifyReport, verify_log

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "lab/compose/docker-compose.yml")]
RUN = ROOT / "lab/.run"
LEDGER = "/var/lib/tools/ledger.jsonl"
# Where each profile's gateway keeps its log and anchor: (service, log, anchor).
LOCATIONS = {
    "reference": (
        "gateway",
        "/var/lib/gateway/log/audit.jsonl",
        "/var/lib/gateway/anchor/head.json",
    ),
    "colocated": ("agent", "/home/agent/.gateway/audit.jsonl", "/home/agent/.gateway/head.json"),
}
LOCATIONS["breach"] = LOCATIONS["reference"]
COMPOSE_FILES = {
    "reference": ["lab/compose/docker-compose.yml"],
    "colocated": ["lab/compose/docker-compose.yml", "lab/compose/colocated.yml"],
    "breach": ["lab/compose/docker-compose.yml", "lab/compose/breach.yml"],
}
_profile = "reference"


def set_profile(profile: str) -> None:
    global COMPOSE, _profile
    _profile = profile
    COMPOSE = ["docker", "compose"] + [
        x for f in COMPOSE_FILES[profile] for x in ("-f", str(ROOT / f))
    ]


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*COMPOSE, *args], capture_output=True, text=True, check=check)


def _jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"_unparseable": line})
    return out


def copy_out(service: str, path: str, dest: Path) -> bool:
    return compose("cp", f"{service}:{path}", str(dest), check=False).returncode == 0


@dataclass
class Snapshot:
    ledger: list[dict]
    audit: list[dict]
    verify: VerifyReport | None
    events: list[dict] = field(default_factory=list)


def ledger() -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "ledger.jsonl"
        return _jsonl(dest.read_text()) if copy_out("tools", LEDGER, dest) else []


def docker_events(since: float) -> list[dict]:
    project = "mcp-gateway-lab"
    r = subprocess.run(
        [
            "docker",
            "events",
            "--since",
            str(int(since)),
            "--until",
            str(int(time.time()) + 1),
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "type=container",
            "--format",
            "{{json .}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    events = []
    for e in _jsonl(r.stdout):
        attrs = e.get("Actor", {}).get("Attributes", {})
        if e.get("Action") in {"kill", "die", "stop", "start", "restart", "pause", "unpause"}:
            events.append(
                {
                    "action": e["Action"],
                    "service": attrs.get("com.docker.compose.service"),
                    "signal": attrs.get("signal"),
                    "time": e.get("time"),
                }
            )
    return events


def snapshot(since: float, max_gap_ms: int | None = None) -> Snapshot:
    key = bytes.fromhex((RUN / "operator/audit.key").read_text().strip())
    service, log_path, anchor_path = LOCATIONS[_profile]
    with tempfile.TemporaryDirectory() as d:
        log, anchor = Path(d) / "audit.jsonl", Path(d) / "head.json"
        have_log = copy_out(service, log_path, log)
        have_anchor = copy_out(service, anchor_path, anchor)
        audit = _jsonl(log.read_text()) if have_log else []
        report = (
            verify_log(log, key, FileAnchor(anchor).read() if have_anchor else None, max_gap_ms)
            if have_log
            else None
        )
    return Snapshot(ledger=ledger(), audit=audit, verify=report, events=docker_events(since))
