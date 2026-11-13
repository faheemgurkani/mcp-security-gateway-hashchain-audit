"""Canonical JSON (RFC 8785 / JCS).

Hashing ``json.dumps`` output is fragile: key order, whitespace and number
formatting differ between serializers, so the same logical entry could get
two different MACs. JCS gives exactly one byte representation per value.
"""

from typing import Any

import rfc8785


def canonical(obj: Any) -> bytes:
    return rfc8785.dumps(obj)
