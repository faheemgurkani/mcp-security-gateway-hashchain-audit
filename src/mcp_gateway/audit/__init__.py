"""Tamper-evident audit log: RFC 8785 canonical JSONL with an HMAC-SHA256 chain (D-007)."""

from mcp_gateway.audit.anchor import FileAnchor, Head
from mcp_gateway.audit.chain import GENESIS_MAC, AuditChain, AuditWriteError
from mcp_gateway.audit.verify import Issue, VerifyReport, verify_log

__all__ = [
    "GENESIS_MAC",
    "AuditChain",
    "AuditWriteError",
    "FileAnchor",
    "Head",
    "Issue",
    "VerifyReport",
    "verify_log",
]
