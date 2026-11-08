"""Append-only HMAC hash chain.

Each JSONL line is one entry:

    {"v": 1, "seq": n, "ts_ms": ..., "type": ..., "session": ..., "payload": {...},
     "prev_mac": <mac of entry n-1>, "mac": HMAC-SHA256(key, JCS(entry without "mac"))}

Editing, deleting or reordering any entry breaks the seq sequence or a
``prev_mac`` link; recomputing the chain needs the key, which only the
gateway's OS user holds. Writes are fsync'd and any failure raises
``AuditWriteError`` so callers can fail closed: a call that cannot be
recorded must not be executed.
"""

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from mcp_gateway.audit.anchor import FileAnchor, Head
from mcp_gateway.audit.canonical import canonical

GENESIS_MAC = "0" * 64
FORMAT_VERSION = 1


class AuditWriteError(RuntimeError):
    """The entry could not be durably recorded; the caller must fail closed."""


def compute_mac(key: bytes, entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "mac"}
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


class AuditChain:
    def __init__(
        self,
        path: str | os.PathLike[str],
        key: bytes,
        anchor: FileAnchor | None = None,
    ):
        if len(key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self.path = Path(path)
        self._key = key
        self._anchor = anchor
        self._lock = threading.Lock()
        self._seq, self._prev_mac = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Continue an existing log after a restart instead of starting a new chain."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS_MAC
        last = None
        with open(self.path, "rb") as f:
            for line in f:
                if line.strip():
                    last = line
        entry = json.loads(last)
        return int(entry["seq"]) + 1, str(entry["mac"])

    @property
    def head(self) -> Head | None:
        return None if self._seq == 0 else Head(seq=self._seq - 1, mac=self._prev_mac)

    def append(
        self, type_: str, payload: dict[str, Any], session: str | None = None
    ) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "v": FORMAT_VERSION,
                "seq": self._seq,
                "ts_ms": time.time_ns() // 1_000_000,  # integer: no float formatting ambiguity
                "type": type_,
                "session": session,
                "payload": payload,
                "prev_mac": self._prev_mac,
            }
            entry["mac"] = compute_mac(self._key, entry)
            try:
                line = canonical(entry) + b"\n"
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if self._anchor is not None:
                    self._anchor.write(Head(seq=entry["seq"], mac=entry["mac"]))
            except (OSError, TypeError, ValueError) as e:
                raise AuditWriteError(f"audit write failed: {e}") from e
            self._seq += 1
            self._prev_mac = entry["mac"]
            return entry
