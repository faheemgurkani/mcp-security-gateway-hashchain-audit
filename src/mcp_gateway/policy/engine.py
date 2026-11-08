"""Least-privilege tool policy: default deny, role -> allowed tool patterns.

    roles:
      user:  {allow: ["crm.*"]}
      admin: {allow: ["crm.*", "admin.*"]}

A tool is callable only if the session's role has a matching pattern. The
policy hash is logged at gateway start so the verifier knows which rules
were in force.
"""

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mcp_gateway.audit.canonical import canonical


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class Policy:
    def __init__(self, data: dict[str, Any]):
        self._data = data
        self._roles: dict[str, list[str]] = {
            role: list(spec.get("allow", [])) for role, spec in data.get("roles", {}).items()
        }

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        return cls(yaml.safe_load(Path(path).read_text()) or {})

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical(self._data)).hexdigest()

    def is_visible(self, role: str, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, p) for p in self._roles.get(role, []))

    def decide(self, role: str, tool: str) -> Decision:
        if role not in self._roles:
            return Decision(False, f"unknown role {role!r}")
        if self.is_visible(role, tool):
            return Decision(True, "allowed by policy")
        return Decision(False, f"role {role!r} may not call {tool!r}")
