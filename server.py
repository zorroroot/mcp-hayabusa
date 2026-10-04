#!/usr/bin/env python3
"""MCP server exposing Hayabusa EVTX analysis.

Written against mcp 2.x, where the server class is `MCPServer` (v1's `FastMCP`
was renamed).

This is a stdio server: run directly it blocks on stdin and prints nothing,
which is correct, not a hang. An MCP client spawns it and speaks JSON-RPC over
the pipe. To exercise it locally:

    python tests/test_server_stdio.py
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

# Hayabusa severity levels, lowest to highest. `--min-level --help` documents
# only the first five, but the CLI accepts `emergency` and `config/level_color.txt`
# lists it -- it MUST rank above critical here, or emergency findings would be
# filtered out by a `critical` floor.
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical", "emergency"]
RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

Severity = Literal["informational", "low", "medium", "high", "critical", "emergency"]

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
MANIFEST = HAYABUSA_DIR / ".hayabusa-release.json"

# A full scan loads ~2,400 rules and can run for minutes on a large EVTX.
# Unbounded, a hung scan would wedge the server with no way for the client out.
SCAN_TIMEOUT_SECONDS = 900

# Findings are returned inline to a model; a noisy scan can produce tens of
# thousands. Cap the payload and report the cap rather than truncating silently.
MAX_FINDINGS = 1000

ANSI = re.compile(r"\x1b\[[0-9;]*m")
EVENT_COUNTS = re.compile(
    r"Events with hits\s*/\s*Total events:\s*([\d,]+)\s*/\s*([\d,]+)"
)

server = MCPServer(
    name="hayabusa",
    version="0.1.0",
    instructions=(
        "Analyze Windows EVTX event logs with Hayabusa, a Sigma-based threat "
        "hunting and forensics timeline generator."
    ),
)


def hayabusa_binary() -> Path:
    """Resolve the Hayabusa executable.

    Release binaries are named for their version and platform (e.g.
    `hayabusa-4.1.0-win-x64.exe`), so the plain `hayabusa`/`hayabusa.exe` name
    usually does *not* exist. `scripts/fetch_hayabusa.py` records the real name
    in `.hayabusa-release.json`; a plain-named binary is accepted as a fallback
    for a hand-placed install.
    """
    if MANIFEST.exists():
        try:
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            binary = HAYABUSA_DIR / manifest["binary"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise ToolError(f"Malformed {MANIFEST.name}: {exc}") from exc
        if binary.exists():
            return binary
        raise ToolError(
            f"{MANIFEST.name} points at {binary.name}, which is missing. "
            f"Re-run: python scripts/fetch_hayabusa.py --force"
        )

    for name in ("hayabusa.exe", "hayabusa"):
        candidate = HAYABUSA_DIR / name
        if candidate.is_file():
            return candidate

    found = sorted(HAYABUSA_DIR.glob("hayabusa-*"))
    if found:
        return found[0]

    raise ToolError(
        f"Hayabusa is not installed -- no executable in {HAYABUSA_DIR} and no "
        f"{MANIFEST.name}. Run: python scripts/fetch_hayabusa.py"
    )


def normalize_level(value: Any) -> str | None:
    """Map a Level as it appears in output to its canonical name.

    Hayabusa *abbreviates* levels in its JSON output -- `info`, `med` are what
    actually come back, not `informational`, `medium`. Matching on the full
    names alone silently mis-ranks those, so resolve by unique prefix, which
    also covers `crit`/`emer` without hardcoding every abbreviation. Returns
    None for anything unrecognized.
    """
    text = str(value).strip().lower()
    if text in RANK:
        return text
    matches = [name for name in SEVERITY_ORDER if name.startswith(text)]
    return matches[0] if len(matches) == 1 and text else None


def _read_findings(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Parse Hayabusa's JSONL output. Returns (findings, unparsable_line_count)."""
    if not path.exists():
        return [], 0
    findings: list[dict[str, Any]] = []
    bad = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    return findings, bad


@server.tool(name="scan_evtx")
def scan_evtx(
    path: Annotated[str, Field(
        description="Path to a single .evtx file, or a directory containing them.",
    )],
    min_severity: Annotated[Severity, Field(
        description=(
            "Lowest severity to report. Defaults to 'informational', which "
            "reports everything."
        ),
    )] = "informational",
) -> dict[str, Any]:
    """Scan a Windows EVTX file, or a directory of them, with Hayabusa and
    return the detections as structured JSON. Optionally filter to detections
    at or above a minimum severity level.
    """
    target = Path(path).expanduser()
    if not target.exists():
        raise ToolError(f"No such file or directory: {path}")

    binary = hayabusa_binary()
    rules = HAYABUSA_DIR / "rules"
    if not rules.is_dir():
        raise ToolError(
            f"Hayabusa rules directory is missing ({rules}). "
            f"Re-run: python scripts/fetch_hayabusa.py --force"
        )

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        out_file = tmpdir / "timeline.jsonl"
        cmd = [
            str(binary), "dfir-timeline",
            "--directory" if target.is_dir() else "--file", str(target),
            "--output-type", "jsonl",
            "--output", str(out_file),
            "--min-level", min_severity,
            # Absolute: the defaults are ./rules and ./rules/config, relative
            # to cwd, and cwd is the temp dir below.
            "--rules", str(rules),
            "--rules-config", str(rules / "config"),
            "--no-wizard",   # otherwise it prompts and the subprocess hangs
            "--utc",         # timestamps are local time by default
            "--no-color",
            "--clobber",
        ]

        try:
            # capture_output is load-bearing: inherited stdout would put
            # Hayabusa's ASCII-art banner on the JSON-RPC channel. cwd=tmpdir
            # keeps its logs/errorlog-*.log out of the project directory.
            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace",
                cwd=tmpdir, timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Hayabusa timed out after {SCAN_TIMEOUT_SECONDS}s scanning {target}."
            ) from exc
        except OSError as exc:
            raise ToolError(f"Could not execute {binary}: {exc}") from exc

        stdout = ANSI.sub("", proc.stdout or "")
        stderr = ANSI.sub("", proc.stderr or "").strip()

        if proc.returncode != 0:
            tail = stderr or " ".join(stdout.strip().splitlines()[-3:]) or "no output"
            raise ToolError(f"Hayabusa exited {proc.returncode}: {tail}")

        findings, unparsable = _read_findings(out_file)

        # Hayabusa writes an error log and still exits 0 -- a corrupt EVTX
        # yields zero findings AND a success code, which would otherwise be
        # reported to the caller as "nothing found".
        error_log = ""
        for log in sorted(tmpdir.glob("logs/errorlog-*.log")):
            error_log = log.read_text(encoding="utf-8", errors="replace").strip()
            break

        hits = total = None
        if m := EVENT_COUNTS.search(stdout):
            hits = int(m.group(1).replace(",", ""))
            total = int(m.group(2).replace(",", ""))

    # `--min-level` filters which rules load; re-filter the results so the
    # contract holds regardless of how Hayabusa interprets the flag. An
    # unrecognized level is kept, never dropped -- under-reporting a finding is
    # worse than reporting one the caller did not ask for.
    floor = RANK[min_severity]
    counts: dict[str, int] = {}
    unknown_levels: set[str] = set()
    kept: list[dict[str, Any]] = []
    for finding in findings:
        level = normalize_level(finding.get("Level", ""))
        if level is None:
            unknown_levels.add(str(finding.get("Level", "")))
        elif RANK[level] < floor:
            continue
        key = level or "unknown"
        counts[key] = counts.get(key, 0) + 1
        kept.append(finding)

    warnings: list[str] = []
    if unknown_levels:
        warnings.append(
            f"Unrecognized severity level(s) {sorted(unknown_levels)} were kept "
            f"rather than filtered out."
        )
    if unparsable:
        warnings.append(f"{unparsable} output line(s) were not valid JSON.")
    if error_log:
        warnings.append(f"Hayabusa reported errors: {error_log[:2000]}")
    if total == 0 and target.is_file():
        warnings.append(
            "Hayabusa read 0 events from this file. It is likely not a valid "
            "EVTX file or is empty -- a zero-finding result here does NOT mean "
            "the log is clean."
        )

    return {
        "target": str(target),
        "min_severity": min_severity,
        "events_scanned": total,
        "events_with_hits": hits,
        "finding_count": len(kept),
        "severity_counts": {
            lvl: counts[lvl]
            for lvl in [*reversed(SEVERITY_ORDER), "unknown"]
            if lvl in counts
        },
        "findings": kept[:MAX_FINDINGS],
        "truncated": len(kept) > MAX_FINDINGS,
        "warnings": warnings,
    }


def main() -> None:
    # stdio transport: stdout IS the JSON-RPC channel. Never print() from
    # server code -- it corrupts the protocol frame. Log to stderr instead.
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
