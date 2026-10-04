#!/usr/bin/env python3
"""End-to-end check of server.py over stdio.

Spawns the server as a real subprocess and drives it with an MCP client, so the
handshake, `main()`, and the stdio transport are all exercised -- calling
`server.call_tool()` in-process skips all three, and it *raises* ToolError where
a real session returns a result with `is_error=True`.

`_collect` only gathers facts; every assertion runs afterwards, outside the
anyio task group. Asserting inside gets the AssertionError wrapped in nested
ExceptionGroups, which buries the message that says what actually broke.

Deliberately fixture-free: no EVTX file is required, so this stays fast and
runs anywhere. Scans against real EVTX data are verified manually.

Runs under pytest, or directly as a script. The test functions are sync and
own their event loop, so no async pytest plugin is needed.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT = Path(__file__).resolve().parent.parent
SERVER = PROJECT / "server.py"

sys.path.insert(0, str(PROJECT))

SEVERITIES = ["informational", "low", "medium", "high", "critical", "emergency"]


async def _collect() -> dict[str, Any]:
    """Drive the server over stdio and return what it reported."""
    params = StdioServerParameters(
        command=sys.executable, args=[str(SERVER)], cwd=str(PROJECT)
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = (await session.list_tools()).tools

            calls = {}
            for label, args in {
                "bad_path": {"path": "does-not-exist.evtx"},
                "bad_severity": {"path": ".", "min_severity": "bogus"},
            }.items():
                res = await session.call_tool("scan_evtx", args)
                calls[label] = (res.is_error, res.content[0].text)

            return {
                "name": init.server_info.name,
                "tools": [t.name for t in tools],
                "schema": tools[0].input_schema if tools else None,
                "calls": calls,
                # The server survived the failed calls.
                "alive": bool((await session.list_tools()).tools),
            }


def test_server_stdio() -> None:
    got = asyncio.run(_collect())

    assert got["name"] == "hayabusa", got["name"]
    assert got["tools"] == ["scan_evtx"], got["tools"]

    schema = got["schema"]
    assert schema["required"] == ["path"], schema["required"]
    assert schema["properties"]["min_severity"]["enum"] == SEVERITIES, schema["properties"]
    # Params must carry descriptions: a decorator `description=` would override
    # the docstring and leave these blank.
    for prop in ("path", "min_severity"):
        assert schema["properties"][prop].get("description"), f"{prop} has no description"

    is_error, text = got["calls"]["bad_path"]
    assert is_error and "No such file or directory" in text, text

    is_error, text = got["calls"]["bad_severity"]
    assert is_error and "Input should be" in text, text

    assert got["alive"], "server did not survive the failed calls"


def test_level_normalization() -> None:
    """Hayabusa abbreviates levels in JSON output (`info`, `med`, ...).

    Getting this wrong mis-ranks findings: an unranked `emer` under a
    `critical` floor would drop the most severe detections there are.
    """
    from server import RANK, normalize_level

    for abbrev, expected in [
        ("info", "informational"), ("low", "low"), ("med", "medium"),
        ("high", "high"), ("crit", "critical"), ("emer", "emergency"),
    ]:
        assert normalize_level(abbrev) == expected, abbrev
        assert normalize_level(expected) == expected, expected

    assert normalize_level("INFO") == "informational"
    assert normalize_level(" High ") == "high"
    for junk in ("", "bogus", "xyz", None):
        assert normalize_level(junk) is None, junk

    # emergency must outrank critical, or a critical floor discards it.
    assert RANK["emergency"] > RANK["critical"]


if __name__ == "__main__":
    test_server_stdio()
    test_level_normalization()
    print("ok: handshake, tool listing, schema, error paths, level ranking")
