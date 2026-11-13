"""Audit built distributions before they are published.

Usage: python scripts/check_dist.py dist/

Fails if a wheel or sdist contains a local-only or sensitive file, or a file outside
the expected layout. Run it after `uv build`, and in the release workflow.
"""

import re
import sys
import tarfile
import zipfile
from pathlib import Path

# Never ship: local notes, secrets, lab results, external gateway installs, the
# embargoed adapter.
FORBIDDEN = re.compile(
    r"(^|/)(CLAUDE\.md|TODO\.md|\.env[^/]*|lab/|embargoed[^/]*|[^/]*\.key)$|(^|/)lab/"
)
WHEEL_TOP = {"mcp_lab"}
SDIST_TOP = {
    "src",
    "tests",
    "examples",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CITATION.cff",
    "pyproject.toml",
    "PKG-INFO",
    ".gitignore",
}


def names(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as z:
            return z.namelist()
    with tarfile.open(path) as t:
        # Drop the leading "<name>-<version>/" directory.
        return [n.split("/", 1)[1] for n in t.getnames() if "/" in n]


def main(dist: Path) -> int:
    problems = []
    files = sorted(dist.glob("*.whl")) + sorted(dist.glob("*.tar.gz"))
    if not files:
        print(f"no distributions in {dist}")
        return 1
    for f in files:
        listed = names(f)
        for n in listed:
            if FORBIDDEN.search(n):
                problems.append(f"{f.name}: forbidden file {n}")
            top = n.split("/", 1)[0]
            if f.suffix == ".whl":
                if top not in WHEEL_TOP and not top.endswith(".dist-info"):
                    problems.append(f"{f.name}: unexpected top-level {top}")
            elif top not in SDIST_TOP:
                problems.append(f"{f.name}: unexpected top-level {top}")
        print(f"{f.name}: {len(listed)} files")
    for p in problems:
        print("  " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "dist")))
