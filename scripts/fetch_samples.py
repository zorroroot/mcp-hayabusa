#!/usr/bin/env python3
"""Download sample EVTX files for testing into ./samples/.

Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES -- public Windows
event logs captured from simulated attacks, mapped to MITRE ATT&CK techniques.
They contain real detections, so they exercise the scanner properly where a
clean system log mostly does not.

Files are selected by rule (the N smallest per ATT&CK category), not by a
hardcoded list, so this keeps working as the upstream repo changes. Category
directories are flattened into a `Category__Filename.evtx` naming scheme.

Usage:
    python scripts/fetch_samples.py                 # 2 per category (~1.4 MB)
    python scripts/fetch_samples.py --per-category 5
    python scripts/fetch_samples.py --all           # all 278 files (~49 MB)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "sbousseaden/EVTX-ATTACK-SAMPLES"
BRANCH = "master"
TREE = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
UA = "mcp-hayabusa-fetch"

EVTX_MAGIC = b"ElfFile\x00"


def github_json(url: str) -> dict:
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), timeout=60
        ) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 403 and not token:
            raise SystemExit(
                "GitHub API rate limit hit (60 requests/hour unauthenticated). "
                "Set GITHUB_TOKEN to raise it."
            ) from e
        raise SystemExit(f"GitHub API request failed: {e.code} {e.reason}") from e


def flat_name(path: str) -> str:
    """'Defense Evasion/DE_104_cleared.evtx' -> 'Defense_Evasion__DE_104_cleared.evtx'."""
    parts = path.split("/")
    category = parts[0].replace(" ", "_")
    stem = parts[-1].replace(" ", "_")
    name = f"{category}__{stem}" if len(parts) > 1 else stem
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=Path("samples"),
                    help="download directory (default: ./samples)")
    ap.add_argument("--per-category", type=int, default=2,
                    help="smallest N files from each ATT&CK category (default: 2)")
    ap.add_argument("--all", action="store_true", help="download every sample (~49 MB)")
    ap.add_argument("--force", action="store_true", help="re-download existing files")
    args = ap.parse_args()

    tree = github_json(TREE)
    if tree.get("truncated"):
        print("warning: GitHub truncated the file listing", file=sys.stderr)

    evtx = [b for b in tree["tree"] if b["path"].lower().endswith(".evtx")]
    if not evtx:
        raise SystemExit("No .evtx files found in the upstream repository.")

    if args.all:
        picks = sorted(evtx, key=lambda b: b["path"])
    else:
        by_category: dict[str, list[dict]] = {}
        for blob in evtx:
            parts = blob["path"].split("/")
            if len(parts) > 1:  # skip loose files at the repo root
                by_category.setdefault(parts[0], []).append(blob)
        picks = [
            blob
            for category in sorted(by_category)
            for blob in sorted(by_category[category],
                               key=lambda b: (b["size"], b["path"]))[:args.per_category]
        ]

    args.dest.mkdir(parents=True, exist_ok=True)
    print(f"{len(picks)} sample(s), {sum(b['size'] for b in picks) / 1e6:.2f} MB "
          f"-> {args.dest}/")

    downloaded = skipped = 0
    for blob in picks:
        out = args.dest / flat_name(blob["path"])
        if out.exists() and not args.force:
            skipped += 1
            continue
        url = RAW + urllib.parse.quote(blob["path"])
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
        except urllib.error.URLError as e:
            print(f"  FAILED {blob['path']}: {e}", file=sys.stderr)
            continue
        # Guard against a 404 page or LFS pointer landing as a .evtx file.
        if not data.startswith(EVTX_MAGIC):
            print(f"  SKIPPED {blob['path']}: not an EVTX file "
                  f"(starts with {data[:16]!r})", file=sys.stderr)
            continue
        out.write_bytes(data)
        downloaded += 1
        print(f"  {len(data):>8,}  {out.name}")

    print(f"\nDownloaded {downloaded}, skipped {skipped} already present.")
    print(f"Scan them with: python tests/test_scan_samples.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
