"""Periodic heartbeat entries.

A gap between consecutive entries longer than a few heartbeat intervals means
the gateway was not running (killed or paused): attack A5. ``verify_log``
reports it as ``time_gap`` when given ``max_gap_ms``.
"""

import anyio

from mcp_lab.gateway.audit.chain import AuditChain


async def run_heartbeat(chain: AuditChain, interval_s: float) -> None:
    n = 0
    while True:
        await anyio.sleep(interval_s)
        n += 1
        chain.append("heartbeat", {"n": n})
