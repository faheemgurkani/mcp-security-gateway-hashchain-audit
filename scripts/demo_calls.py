"""Make a handful of allowed and forbidden calls through a running gateway (used by run_demo.sh).

uv run python scripts/demo_calls.py URL USER_TOKEN ADMIN_TOKEN
"""

import sys

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


def client(url: str, token: str) -> Client:
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(30, read=300)
    )
    return Client(streamable_http_client(url, http_client=http))


async def call(c: Client, label: str, tool: str, args: dict) -> None:
    r = await c.call_tool(tool, args)
    verdict = "DENIED " if r.is_error else "ALLOWED"
    print(f"  {verdict} {label:42} {r.content[0].text[:70]}")


async def main(url: str, user: str, admin: str) -> None:
    async with client(url, user) as c:
        names = sorted(t.name for t in (await c.list_tools()).tools)
        print(f"  user sees tools: {names}  (admin tools hidden)")
        await call(c, "user: crm.lookup", "crm.lookup", {"customer_id": "C1001"})
        await call(
            c,
            "user: admin.delete_user (confused deputy)",
            "admin.delete_user",
            {"user_id": "U2001"},
        )
        await call(
            c,
            "user: claims role=admin in arguments",
            "crm.lookup",
            {"customer_id": "C1001", "role": "admin"},
        )
        await call(
            c,
            "user: smuggles field=password",
            "crm.update",
            {"customer_id": "C1001", "field": "password", "value": "x"},
        )
    async with client(url, "forged-token") as c:
        await call(c, "forged token: crm.lookup", "crm.lookup", {"customer_id": "C1001"})
    async with client(url, admin) as c:
        await call(c, "admin: admin.delete_user", "admin.delete_user", {"user_id": "U2001"})


if __name__ == "__main__":
    anyio.run(main, *sys.argv[1:4])
