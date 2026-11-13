"""Generate per-run lab secrets in lab/.run/ (git-ignored).

    gateway/  audit.key, sessions.yaml (token hashes only), upstream_token
    tools/    upstream_token        (the only caller the tool zone accepts)
    agent/    mcp.json              (agent's own MCP config: gateway URL + user token)
    operator/ admin_token, audit.key (for the harness/observer; never mounted into the agent)
    colocated/ audit.key, sessions.yaml, upstream_token: only for the colocated profile,
              where these sit on the agent's disk by design

Re-running rotates everything, so each scorecard run starts clean.
"""

import argparse
import json
import secrets
import shutil
from pathlib import Path

import yaml

from mcp_lab.gateway.identity import hash_token

RUN = Path(__file__).parent / ".run"
GATEWAY_URLS = {
    "reference": "http://gateway:8000/mcp",
    "breach": "http://gateway:8000/mcp",
    "colocated": "http://127.0.0.1:8000/mcp",
}


def write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def main(profile: str = "reference") -> None:
    if RUN.exists():
        shutil.rmtree(RUN)
    key = secrets.token_hex(32)
    upstream = secrets.token_urlsafe(32)
    user_token, admin_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    # 0644: the containers run as different UIDs than the host user; on a
    # multi-user host you'd use docker secrets instead.
    write(RUN / "gateway/audit.key", key)
    write(RUN / "gateway/upstream_token", upstream)
    sessions = yaml.safe_dump(
        {
            "sessions": [
                {
                    "principal": "agent-alice",
                    "role": "user",
                    "token_sha256": hash_token(user_token),
                },
                {
                    "principal": "operator",
                    "role": "admin",
                    "token_sha256": hash_token(admin_token),
                },
            ]
        },
        sort_keys=False,
    )
    write(RUN / "gateway/sessions.yaml", sessions)
    write(RUN / "tools/upstream_token", upstream)
    if profile == "colocated":
        write(RUN / "colocated/audit.key", key)
        write(RUN / "colocated/sessions.yaml", sessions)
        write(RUN / "colocated/upstream_token", upstream)
    write(
        RUN / "agent/mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "crm": {
                        "url": GATEWAY_URLS[profile],
                        "headers": {"Authorization": f"Bearer {user_token}"},
                    }
                }
            },
            indent=2,
        ),
        0o666,  # the agent must be able to edit its own config (A4)
    )
    write(RUN / "operator/admin_token", admin_token)
    write(RUN / "operator/audit.key", key)
    print(f"lab secrets written to {RUN}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=sorted(GATEWAY_URLS), default="reference")
    main(ap.parse_args().profile)
