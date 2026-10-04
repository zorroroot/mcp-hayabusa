#!/usr/bin/env python3
"""Call scan_evtx directly against real attack-sample EVTX files.

Imports server.py in-process and calls the tool function -- the complement to
test_server_stdio.py, which covers the protocol but no real scanning.

Needs ./samples/. Get them with:

    python scripts/fetch_samples.py

Each scan loads ~2,400 rules, so the bulk of the work is one directory scan
rather than 20 single-file scans.

Runs under pytest, or directly as a script:

    pytest tests/test_scan_samples.py
    python tests/test_scan_samples.py      # same checks, plus a summary report
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from server import SEVERITY_ORDER, scan_evtx  # noqa: E402

SAMPLES = PROJECT / "samples"


def _skip(msg: str) -> None:
    """Skip under pytest; exit with the message when run as a script."""
    try:
        import pytest
    except ImportError:
        raise SystemExit(msg) from None
    pytest.skip(msg)


def _require_samples() -> None:
    if not SAMPLES.is_dir() or not list(SAMPLES.glob("*.evtx")):
        _skip(f"No samples in {SAMPLES}/. Run: python scripts/fetch_samples.py")


def test_scan_directory() -> None:
    """One scan over every sample: these are attack captures, so they must hit."""
    _require_samples()
    result = scan_evtx(str(SAMPLES))

    assert result["events_scanned"], "no events were read from the samples"
    assert result["finding_count"] > 0, "attack samples produced no detections"
    assert not result["warnings"], result["warnings"]
    assert sum(result["severity_counts"].values()) == result["finding_count"]

    # Every reported level must be one we rank; an unranked level would mean
    # findings are being mis-sorted (or dropped) by the severity filter.
    for level in result["severity_counts"]:
        assert level in SEVERITY_ORDER, f"unranked level: {level}"


def test_severity_filter_is_monotonic() -> None:
    """Raising the floor can only ever narrow the result set."""
    _require_samples()
    counts = [scan_evtx(str(SAMPLES), lvl)["finding_count"]
              for lvl in ["informational", "low", "medium", "high"]]
    assert counts == sorted(counts, reverse=True), counts


def test_single_file_detects_log_clearing() -> None:
    """A named sample fires the rule it was captured to demonstrate."""
    _require_samples()
    sample = SAMPLES / "Defense_Evasion__DE_104_system_log_cleared.evtx"
    if not sample.exists():
        # Upstream renamed it; the directory scan still covers this ground.
        _skip(f"{sample.name} not in ./samples/")

    result = scan_evtx(str(sample), "medium")
    titles = [f.get("RuleTitle", "") for f in result["findings"]]
    assert any("clear" in t.lower() for t in titles), titles


def test_missing_file_raises() -> None:
    from mcp.server.mcpserver.exceptions import ToolError
    try:
        scan_evtx(str(SAMPLES / "does-not-exist.evtx"))
    except ToolError as exc:
        assert "No such file or directory" in str(exc), exc
    else:
        raise AssertionError("expected ToolError for a missing file")


def _report() -> None:
    """Human-readable summary when run as a script."""
    _require_samples()
    files = sorted(SAMPLES.glob("*.evtx"))
    print(f"Scanning {len(files)} sample(s) in {SAMPLES}/\n")

    result = scan_evtx(str(SAMPLES))
    print(f"  events scanned : {result['events_scanned']:,}")
    print(f"  events with hits: {result['events_with_hits']:,}")
    print(f"  findings       : {result['finding_count']:,}"
          f"{' (truncated)' if result['truncated'] else ''}")
    print(f"  by severity    : {result['severity_counts']}")
    if result["warnings"]:
        print(f"  warnings       : {result['warnings']}")

    print("\n  severity filter:")
    for level in ["informational", "low", "medium", "high", "critical"]:
        print(f"    {level:>14}: {scan_evtx(str(SAMPLES), level)['finding_count']:>5}")

    top: dict[str, int] = {}
    for finding in result["findings"]:
        title = finding.get("RuleTitle", "?")
        top[title] = top.get(title, 0) + 1
    print("\n  top detections:")
    for title, n in sorted(top.items(), key=lambda kv: -kv[1])[:8]:
        print(f"    {n:>4}  {title}")


if __name__ == "__main__":
    test_scan_directory()
    test_severity_filter_is_monotonic()
    test_single_file_detects_log_clearing()
    test_missing_file_raises()
    _report()
    print("\nok: all checks passed")
