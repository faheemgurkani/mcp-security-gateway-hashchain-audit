"""Run attack scenarios against a gateway profile and record outcomes.

    uv run python -m lab.scorecard.run --profile reference [--only A1,A8]

Each scenario gets a fresh lab: rotated secrets, empty volumes, warmup calls,
a "before" snapshot, the agent's attack, a settle period, an "after" snapshot.
"""

import argparse
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from lab.attacks.scenarios import BY_ID, SCENARIOS, judge
from lab.observer import collect

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "lab/results"
HEARTBEAT_S = 2


def sh(*cmd: str, env: dict[str, str] | None = None) -> str:
    r = subprocess.run(
        cmd, capture_output=True, text=True, cwd=ROOT, env={**os.environ, **(env or {})}
    )
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def fresh_lab(profile: str, env: dict[str, str]) -> None:
    sh(*collect.COMPOSE, "down", "-v", "--remove-orphans")
    sh("uv", "run", "python", "-m", "lab.setup", "--profile", profile)
    sh(*collect.COMPOSE, "up", "-d", "--wait", env={"HEARTBEAT_S": str(HEARTBEAT_S), **env})


def agent(action: str) -> dict:
    out = sh(*collect.COMPOSE, "exec", "-T", "agent", "python", "-m", "lab.attacks.actions", action)
    return json.loads(out.strip().splitlines()[-1])


def run_one(profile: str, sid: str) -> dict:
    s = BY_ID[sid]
    fresh_lab(profile, s.env or {})
    t0 = time.time()
    agent("warmup")
    time.sleep(HEARTBEAT_S + 0.5)
    max_gap = 3 * HEARTBEAT_S * 1000
    pre = collect.snapshot(t0, max_gap)
    attack = agent(sid)
    time.sleep(2 * HEARTBEAT_S + 0.5)
    post = collect.snapshot(t0, max_gap)
    outcome, evidence = judge(s, pre, post)
    return {
        "id": sid,
        "title": s.title,
        "asi": s.asi,
        "outcome": outcome,
        "evidence": evidence,
        "agent_steps": attack["steps"],
        "verify_issues": [] if post.verify is None else [i.__dict__ for i in post.verify.issues],
        "docker_events": post.events,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="reference", choices=sorted(collect.COMPOSE_FILES))
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    collect.set_profile(args.profile)
    ids = [x for x in args.only.split(",") if x] or [s.id for s in SCENARIOS]
    sh("docker", "build", "-q", "-t", "mcp-gateway-lab:dev", "-f", "lab/compose/Dockerfile", ".")
    results = []
    for sid in ids:
        r = run_one(args.profile, sid)
        print(f"{args.profile:10} {sid:4} {r['outcome']:10} {r['evidence']}", flush=True)
        results.append(r)
    sh(*collect.COMPOSE, "down", "-v", "--remove-orphans")
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"{args.profile}.json"
    # --only re-runs replace just those rows and keep the rest.
    merged = {r["id"]: r for r in json.loads(out.read_text())["results"]} if out.exists() else {}
    merged.update({r["id"]: r for r in results})
    order = [s.id for s in SCENARIOS]
    out.write_text(
        json.dumps(
            {
                "profile": args.profile,
                "run_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "results": sorted(merged.values(), key=lambda r: order.index(r["id"])),
            },
            indent=2,
            default=str,
        )
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
