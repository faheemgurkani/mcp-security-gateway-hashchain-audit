"""Which lab profile is a real deployment in? (``mcp-lab check-deployment``)

Run it **as the agent's OS user, where the agent runs**. It answers the review
questions behind the lab's three profiles without changing anything (it uses
``os.access`` and a TCP connect, never a write):

- can the agent read the signing key or the gateway's own credentials?
- can it write the audit log, or the head anchor?
- can it edit its own MCP config (and drop the gateway from it)?
- can it reach the tool server directly, or signal the gateway process?

and maps the answers to ``reference`` / ``breach`` / ``colocated`` and to the
attacks each one leaves open (scorecard.md).
"""

import contextlib
import json
import os
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Check:
    question: str
    target: str
    exposed: bool | None  # None = not checked
    detail: str
    opens: list[str] = field(default_factory=list)


@dataclass
class DeploymentReport:
    user: str
    checks: list[Check]
    profile: str
    loses: list[str]


def _writable(p: Path) -> tuple[bool, str]:
    if p.exists():
        if os.access(p, os.W_OK):
            return True, "writable"
        if os.access(p.parent, os.W_OK | os.X_OK):
            return True, "file is read-only, but its directory is writable (replace it)"
        return False, "not writable"
    if os.access(p.parent if p.parent.exists() else Path("/"), os.W_OK):
        return True, "does not exist yet, and its directory is writable"
    return False, "does not exist; directory not writable"


def _readable(p: Path) -> tuple[bool, str]:
    if not p.exists():
        return False, "not visible (does not exist from here)"
    return (True, "readable") if os.access(p, os.R_OK) else (False, "exists but not readable")


def _reachable(url: str) -> tuple[bool, str]:
    u = urlparse(url if "://" in url else f"tcp://{url}")
    host, port = u.hostname or "127.0.0.1", u.port or (443 if u.scheme == "https" else 80)
    try:
        socket.create_connection((host, port), timeout=2).close()
        return True, f"{host}:{port} accepts connections"
    except OSError as e:
        return False, f"{host}:{port} unreachable ({e.strerror or e})"


def _same_user_processes(pattern: str) -> list[str]:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        out = subprocess.run(["ps", "-eo", "pid=,uid=,args="], capture_output=True, text=True,
                             timeout=5).stdout  # fmt: skip
        me = os.getuid()
        hits = []
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[1] == str(me) and pattern in parts[2]:
                if "check-deployment" not in parts[2]:
                    hits.append(f"pid {parts[0]}")
        return hits
    return []


def check_deployment(
    key: Path | None = None,
    log: Path | None = None,
    anchor: Path | None = None,
    agent_config: Path | None = None,
    secrets: list[Path] | None = None,
    tool_urls: list[str] | None = None,
    gateway_process: str | None = None,
) -> DeploymentReport:
    checks: list[Check] = []

    def add(question, target, result, opens):
        if result is None:
            checks.append(Check(question, target or "-", None, "not checked (no path given)"))
        else:
            exposed, detail = result
            checks.append(Check(question, target, exposed, detail, opens if exposed else []))

    add(
        "Can the agent read the audit signing key?",
        str(key or ""),
        _readable(key) if key else None,
        ["A11 spoof", "A12 rewrite", "A1-A3 undetected"],
    )
    add(
        "Can the agent write the audit log?",
        str(log or ""),
        _writable(log) if log else None,
        ["A1 edit", "A2 delete", "A3 truncate"],
    )
    add(
        "Can the agent write the head anchor?",
        str(anchor or ""),
        _writable(anchor) if anchor else None,
        ["A3 truncation undetected"],
    )
    add(
        "Can the agent edit its own MCP config?",
        str(agent_config or ""),
        _writable(agent_config) if agent_config else None,
        ["A4 remove the gateway"],
    )
    for s in secrets or []:
        add(
            "Can the agent read a gateway credential?",
            str(s),
            _readable(s),
            ["A6 call tools with the gateway's identity"],
        )
    for url in tool_urls or []:
        add(
            "Can the agent reach the tool server directly?",
            url,
            _reachable(url),
            ["A6 call tools around the gateway"],
        )
    if gateway_process:
        hits = _same_user_processes(gateway_process)
        add("Does the gateway run as the agent's own user?", gateway_process,
            (bool(hits), ", ".join(hits) if hits else "no matching process owned by this user"),
            ["A5 kill the gateway", "read its memory and files"])  # fmt: skip

    def exposed(q: str) -> bool:
        return any(c.exposed for c in checks if c.question.startswith(q))

    key_x = exposed("Can the agent read the audit signing key")
    log_x = exposed("Can the agent write the audit log")
    anchor_x = exposed("Can the agent write the head anchor")
    around = exposed("Can the agent reach the tool server") and (
        exposed("Can the agent read a gateway credential") or exposed("Can the agent edit")
    )
    same_user = exposed("Does the gateway run as")
    loses: list[str] = []
    if key_x or same_user:
        profile = "colocated"
        loses.append("every log attack goes undetected: with the key the agent can rewrite "
                     "history and the verifier still says OK")  # fmt: skip
    elif log_x or anchor_x:
        profile = "breach"
        loses.append("log edits are detected, not prevented")
        if anchor_x:
            loses.append("truncation is undetected: the anchor can be moved back to an "
                         "earlier entry, whose MAC is visible in the log")  # fmt: skip
    else:
        profile = "reference"
    if around:
        loses.append("calls can go around the gateway entirely (the kimi-k3.1-pro path in "
                     "scorecard-llm-models.md): nothing is logged")  # fmt: skip
        if profile == "reference":
            profile = "breach"
    if not any(c.exposed is not None for c in checks):
        profile = "unknown"
    user = os.environ.get("USER") or str(os.getuid())
    return DeploymentReport(user, checks, profile, loses)


def as_text(r: DeploymentReport) -> str:
    mark = {True: "EXPOSED", False: "ok     ", None: "skipped"}
    out = [f"Checked as user {r.user!r} (run this as the agent's user, where the agent runs)", ""]
    for c in r.checks:
        out.append(f"  [{mark[c.exposed]}] {c.question}")
        out.append(f"            {c.target}: {c.detail}")
        if c.opens:
            out.append(f"            opens: {', '.join(c.opens)}")
    out += ["", f"Closest lab profile: {r.profile}"]
    out += [f"  - {x}" for x in r.loses] or ["  - nothing the lab's attacks rely on is exposed"]
    out += [
        "",
        "Every attack under each profile: https://github.com/faheemgurkani/"
        "mcp-security-gateway-hashchain-audit/blob/main/docs/results/scorecard.md",
    ]
    return "\n".join(out)


def as_json(r: DeploymentReport) -> str:
    return json.dumps(
        {"user": r.user, "profile": r.profile, "loses": r.loses,
         "checks": [c.__dict__ for c in r.checks]}, indent=2)  # fmt: skip
