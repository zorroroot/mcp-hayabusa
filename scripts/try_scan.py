"""Call scan_evtx directly (no MCP client) against a sample EVTX and print a summary.

Usage:
    python scripts/try_scan.py                              # default sample, server_skeleton
    python scripts/try_scan.py samples/<file>.evtx high     # path, min_severity
    python scripts/try_scan.py samples/ medium --server server

Samples come from https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES;
fetch them with: python scripts/fetch_samples.py
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_SAMPLE = ROOT / "samples" / "Defense_Evasion__DE_104_system_log_cleared.evtx"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", default=str(DEFAULT_SAMPLE))
    parser.add_argument("min_severity", nargs="?", default="informational")
    parser.add_argument("--server", default="server_skeleton",
                        help="module to import scan_evtx from (default: server_skeleton)")
    args = parser.parse_args()

    if not Path(args.path).exists():
        print(f"{args.path} not found. Run: python scripts/fetch_samples.py",
              file=sys.stderr)
        return 1

    module = importlib.import_module(args.server)
    result = module.scan_evtx(args.path, args.min_severity)

    print(f"module:    {args.server}")
    print(f"target:    {result['target']}")
    print(f"backend:   {result['backend']}")
    print(f"findings:  {result['finding_count']} at >= {result['min_severity']}")
    print(f"severity:  {result['severity_counts']}")
    for warning in result["warnings"]:
        print(f"warning:   {warning[:200]}")
    top = Counter(f.get("RuleTitle", "?") for f in result["findings"]).most_common(10)
    if top:
        print("top rules:")
        for title, n in top:
            print(f"  {n:4}  {title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
