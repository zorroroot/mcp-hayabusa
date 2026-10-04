#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/.

The release archives have no wrapper directory -- they unpack `config/`, `rules/`
and a version-and-platform-named executable straight into the destination, e.g.
`hayabusa/hayabusa-4.1.0-win-x64.exe`. Because that name moves with every release,
the script writes `hayabusa/.hayabusa-release.json` recording the resolved binary
path so the MCP server has something stable to read.

Usage:
    python scripts/fetch_hayabusa.py
    python scripts/fetch_hayabusa.py --tag v4.1.0 --force
    python scripts/fetch_hayabusa.py --platform lin-x64-musl --dest /opt/hayabusa
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
API = f"https://api.github.com/repos/{REPO}/releases"
UA = "mcp-hayabusa-fetch"

# Release asset platform slugs, as published by the project. Verified against the
# v4.1.0 asset list; the `-live-response` variants are deliberately not reachable
# here -- they are a cut-down build, not what we want.
PLATFORMS = {
    ("windows", "amd64"): "win-x64",
    ("windows", "x86"): "win-x86",
    ("windows", "arm64"): "win-aarch64",
    ("darwin", "amd64"): "mac-x64",
    ("darwin", "arm64"): "mac-aarch64",
    ("linux", "amd64"): "lin-x64",      # libc suffix appended below
    ("linux", "arm64"): "lin-aarch64",
}

ARCH_ALIASES = {
    "amd64": "amd64", "x86_64": "amd64", "x64": "amd64",
    "arm64": "arm64", "aarch64": "arm64",
    "x86": "x86", "i386": "x86", "i686": "x86",
}


def detect_platform() -> str:
    system = platform.system().lower()
    arch = ARCH_ALIASES.get(platform.machine().lower())
    if arch is None:
        raise SystemExit(f"Unsupported CPU architecture: {platform.machine()!r}")

    slug = PLATFORMS.get((system, arch))
    if slug is None:
        raise SystemExit(
            f"No Hayabusa release for {system}/{arch}. "
            f"Pass --platform explicitly if you know the right asset slug."
        )

    if system == "linux":
        # musl builds are published separately; glibc is the common case.
        libc = "musl" if glob.glob("/lib/ld-musl-*") else "gnu"
        slug = f"{slug}-{libc}"
    return slug


def github_json(url: str) -> dict:
    """Call the GitHub API. A token (if present) is used ONLY here -- never on the
    asset download, whose redirect to the object host rejects forwarded auth."""
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
                "GitHub API rate limit hit (60 requests/hour unauthenticated).\n"
                "Set GITHUB_TOKEN to raise it, or pass --tag to skip the lookup."
            ) from e
        raise SystemExit(f"GitHub API request failed: {e.code} {e.reason}") from e


def download(url: str, dest: Path, expected_size: int) -> str:
    """Stream to disk with progress; return the SHA-256 of what arrived."""
    digest = hashlib.sha256()
    got = 0
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r, dest.open("wb") as f:
        while chunk := r.read(1 << 16):
            f.write(chunk)
            digest.update(chunk)
            got += len(chunk)
            if expected_size and sys.stderr.isatty():
                pct = got * 100 // expected_size
                print(f"\r  {pct:3d}%  {got / 1e6:6.1f} / {expected_size / 1e6:.1f} MB",
                      end="", file=sys.stderr)
    if expected_size and sys.stderr.isatty():
        print(file=sys.stderr)
    if expected_size and got != expected_size:
        raise SystemExit(f"Truncated download: got {got} bytes, expected {expected_size}")
    return digest.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=Path("hayabusa"),
                    help="extraction directory (default: ./hayabusa)")
    ap.add_argument("--tag", help="release tag, e.g. v4.1.0 (default: latest)")
    ap.add_argument("--platform", dest="plat",
                    help="asset platform slug override, e.g. win-x64, lin-x64-musl")
    ap.add_argument("--force", action="store_true",
                    help="replace --dest if it already exists")
    args = ap.parse_args()

    plat = args.plat or detect_platform()
    dest: Path = args.dest

    if dest.exists() and any(dest.iterdir()):
        if not args.force:
            print(f"error: {dest}/ already exists and is not empty. "
                  f"Re-run with --force to replace it.", file=sys.stderr)
            return 1
        print(f"Removing existing {dest}/ (--force)")
        shutil.rmtree(dest)

    url = f"{API}/tags/{args.tag}" if args.tag else f"{API}/latest"
    release = github_json(url)
    tag = release["tag_name"]
    version = tag.lstrip("v")

    # Exact-name match, not a substring test: a substring match on "win-x64"
    # would also hit hayabusa-<v>-win-x64-live-response.zip.
    want = f"hayabusa-{version}-{plat}.zip"
    asset = next((a for a in release["assets"] if a["name"] == want), None)
    if asset is None:
        names = "\n  ".join(a["name"] for a in release["assets"])
        raise SystemExit(f"No asset named {want} in release {tag}.\nAvailable:\n  {names}")

    print(f"Hayabusa {tag} ({plat})")
    print(f"Downloading {asset['name']} ({asset['size'] / 1e6:.1f} MB)")

    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset["name"]
        sha = download(asset["browser_download_url"], archive, asset["size"])
        # Hayabusa publishes no checksum asset, so this is a record of what we
        # received -- not verification against an upstream-published value.
        print(f"  sha256 (as downloaded): {sha}")

        dest.mkdir(parents=True, exist_ok=True)
        print(f"Extracting to {dest}/")
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)

    # zipfile does not preserve the executable bit.
    binary = next((p for p in dest.iterdir()
                   if p.is_file() and p.stem.startswith("hayabusa")), None)
    if binary is None:
        raise SystemExit(f"Extracted archive but found no hayabusa executable in {dest}/")
    if os.name != "nt":
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    manifest = dest / ".hayabusa-release.json"
    manifest.write_text(json.dumps({
        "tag": tag,
        "version": version,
        "platform": plat,
        "binary": str(binary.relative_to(dest)),
    }, indent=2) + "\n", encoding="utf-8")

    print(f"\nInstalled: {binary}")
    print(f"Manifest:  {manifest}")
    print(f"Verify:    {binary} help")   # note: v4.1.0 has no --version flag
    return 0


if __name__ == "__main__":
    sys.exit(main())
