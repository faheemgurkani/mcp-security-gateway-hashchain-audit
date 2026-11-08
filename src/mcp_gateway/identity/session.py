"""Gateway-side session identity (D-006).

The agent presents an opaque bearer token. The gateway maps it to a
principal and role from its own config; the role is never read from the
request. The registry stores only SHA-256 hashes of tokens, so reading the
gateway config doesn't reveal usable tokens.

Identity-looking fields inside tool arguments ("role", "as_user", ...) are
never honoured. They are reported so the attempt can be logged (A7).
"""

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

IMPERSONATION_FIELDS = frozenset(
    {
        "role",
        "user",
        "user_id_override",
        "principal",
        "as_user",
        "on_behalf_of",
        "admin",
        "is_admin",
        "sudo",
        "impersonate",
    }
)


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


class SessionRegistry:
    def __init__(self, entries: dict[str, Principal]):
        self._by_hash = dict(entries)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "SessionRegistry":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            {
                s["token_sha256"]: Principal(name=s["principal"], role=s["role"])
                for s in data.get("sessions", [])
            }
        )

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        return self._by_hash.get(hash_token(token))


def find_impersonation_fields(arguments: dict[str, Any] | None) -> list[str]:
    if not arguments:
        return []
    return sorted(k for k in arguments if k.lower() in IMPERSONATION_FIELDS)
