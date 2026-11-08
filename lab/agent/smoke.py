"""Smoke test run inside the agent container: normal use, then a direct tool-zone probe."""

import anyio

from lab.agent.client import connect


async def main() -> None:
    async with connect() as c:
        print("tools:", sorted(t.name for t in (await c.list_tools()).tools))
        r = await c.call_tool("crm.lookup", {"customer_id": "C1001"})
        print("lookup:", r.is_error, r.content[0].text)
    try:
        with anyio.fail_after(5):
            async with connect(url="http://tools:9000/mcp") as c:
                await c.list_tools()
        print("direct tool zone: REACHABLE")
    except Exception as e:  # noqa: BLE001
        print("direct tool zone: unreachable:", type(e).__name__)


anyio.run(main)
