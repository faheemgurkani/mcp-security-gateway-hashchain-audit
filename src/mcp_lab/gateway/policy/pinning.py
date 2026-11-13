"""Tool-definition pinning (rug-pull defence, A10).

At gateway start the upstream tool definitions (name, description, input
schema) are hashed and pinned. If a later listing shows a changed definition
(for example a description that now carries hidden instructions), that tool
is quarantined and calls to it are refused.
"""

import hashlib
from typing import Any

from mcp_lab.gateway.audit.canonical import canonical


def tool_fingerprint(name: str, description: str | None, input_schema: Any) -> str:
    return hashlib.sha256(
        canonical({"name": name, "description": description or "", "input_schema": input_schema})
    ).hexdigest()


class ToolPins:
    def __init__(self, fingerprints: dict[str, str]):
        self.pins = dict(fingerprints)
        self.quarantined: set[str] = set()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical(self.pins)).hexdigest()

    def check(self, current: dict[str, str]) -> list[str]:
        """Compare a fresh listing with the pins; return newly changed tool names."""
        changed = [
            name for name, fp in current.items() if name in self.pins and self.pins[name] != fp
        ]
        changed += [name for name in current if name not in self.pins]
        new = [n for n in changed if n not in self.quarantined]
        self.quarantined.update(changed)
        return new

    def allowed(self, name: str) -> bool:
        return name in self.pins and name not in self.quarantined
