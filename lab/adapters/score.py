"""Score gateways with the shared harness and write lab/results/external.json.

    uv run python -m lab.adapters.score                 # every gateway that is installed
    uv run python -m lab.adapters.score --only shugo    # one (comma-separated for several)

External gateways must be installed first (lab/adapters/README.md). Gateways under
private disclosure (D-013) are written to the git-ignored lab/results/raw/ instead.
"""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from lab.adapters.gateways import ALL, EMBARGOED
from mcp_lab.harness import score

ROOT = Path(__file__).resolve().parents[2]

PUBLIC = ROOT / "lab/results/external.json"
PRIVATE = ROOT / "lab/results/raw/external-embargoed.json"


def _load(p: Path) -> dict[str, dict]:
    return {g["gateway"]: g for g in json.loads(p.read_text())["gateways"]} if p.exists() else {}


def _save(p: Path, by_name: dict[str, dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    order = [n for n in ALL if n in by_name]
    p.write_text(json.dumps({"gateways": [by_name[n] for n in order]}, indent=2) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=",".join(ALL))
    a = ap.parse_args()
    public, private = _load(PUBLIC), _load(PRIVATE)
    for name in a.only.split(","):
        r = score(ALL[name]())
        r["run_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        (private if name in EMBARGOED else public)[name] = r
        public.pop(name, None) if name in EMBARGOED else None
        for x in r["results"]:
            print(f"{name:20} {x['id']:4} {x['outcome']:10} {x['evidence'][:80]}", flush=True)
    _save(PUBLIC, public)
    if private:
        _save(PRIVATE, private)
    print(f"wrote {PUBLIC}" + (f" and {PRIVATE} (embargoed)" if private else ""))


if __name__ == "__main__":
    main()
