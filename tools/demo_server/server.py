"""Compatibility entry point: the demo tool server lives in ``mcp_lab.demo.server``.

``python -m tools.demo_server.server`` keeps working for the Docker lab and old commands.
"""

from mcp_lab.demo.server import run

if __name__ == "__main__":
    run()
