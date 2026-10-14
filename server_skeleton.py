"""Minimal MCP server for mcp-hayabusa -- the simple version of server.py.

`scan_evtx` follows five steps: verify the path, run Hayabusa, filter by
severity, return JSON, handle errors. server.py is the full version (backend
override, error-log and event-count checks, result cap, timeouts per backend).

Two corrections to the usual tutorial assumptions, verified against v4.1.0:

* There is no `json-timeline` subcommand in Hayabusa 4.x. The equivalent is
  `dfir-timeline --output-type jsonl`.
* The binary is not `./hayabusa/hayabusa(.exe)`. Its name carries the version
  (`hayabusa-4.1.0-win-x64.exe`), so it is read from the manifest that
  scripts/fetch_hayabusa.py writes.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical", "emergency"]
Severity = Literal["informational", "low", "medium", "high", "critical", "emergency"]

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
WSL_HAYABUSA_DIR = "~/hayabusa"   # Linux build, used when Windows blocks the .exe
APP_CONTROL_WINERROR = 4551       # Smart App Control refusing an unsigned binary
TIMEOUT_SECONDS = 900

server = MCPServer(
    "hayabusa",
    instructions=(
        "Analyze Windows EVTX event logs with Hayabusa, a Sigma-based threat "
        "hunting and forensics timeline generator."
    ),
)


def find_windows_binary() -> Path:
    """Locate the native binary via the manifest fetch_hayabusa.py writes."""
    manifest = HAYABUSA_DIR / ".hayabusa-release.json"
    if not manifest.exists():
        raise ToolError(
            "Hayabusa is not installed. Run: python scripts/fetch_hayabusa.py"
        )
    binary = HAYABUSA_DIR / json.loads(manifest.read_text(encoding="utf-8"))["binary"]
    if not binary.exists():
        raise ToolError(f"Hayabusa binary {binary.name} is missing. Re-run "
                        "python scripts/fetch_hayabusa.py --force")
    return binary


def to_wsl_path(path: Path) -> str:
    r"""C:\Users\x -> /mnt/c/Users/x"""
    drive, rest = os.path.splitdrive(str(path.resolve()))
    return f"/mnt/{drive[0].lower()}{rest.replace(chr(92), '/')}"


def find_wsl_binary() -> str:
    """Ask WSL where its Hayabusa is. `~` only expands in a Linux shell."""
    script = f'cd {WSL_HAYABUSA_DIR} && printf "%s/" "$PWD" && cat .hayabusa-release.json'
    proc = subprocess.run(["wsl.exe", "-e", "bash", "-lc", script],
                          capture_output=True, text=True, errors="replace")
    out = proc.stdout.replace("\x00", "")   # wsl.exe can emit UTF-16
    if proc.returncode != 0:
        raise ToolError(
            f"Hayabusa is not installed in WSL at {WSL_HAYABUSA_DIR}. Inside WSL "
            f"run: python3 scripts/fetch_hayabusa.py --dest {WSL_HAYABUSA_DIR}"
        )
    directory, _, manifest = out.partition("/{")
    return f"{directory}/{json.loads('{' + manifest)['binary']}"


def hayabusa_args(binary: str, rules: str, target: str, output: str,
                  is_dir: bool, min_severity: str) -> list[str]:
    return [
        binary, "dfir-timeline",
        "--directory" if is_dir else "--file", target,
        "--output-type", "jsonl", "--output", output,
        "--min-level", min_severity,
        # Absolute rules paths: the defaults are relative to cwd.
        "--rules", rules, "--rules-config", f"{rules}/config",
        "--no-wizard",   # without it Hayabusa prompts and hangs forever
        "--utc", "--no-color", "--clobber",
    ]


def run_hayabusa(target: Path, out_file: Path, tmpdir: Path,
                 min_severity: str) -> tuple[subprocess.CompletedProcess, str]:
    """Run natively; fall back to WSL if Windows blocks the binary."""
    binary = find_windows_binary()
    argv = hayabusa_args(str(binary), (HAYABUSA_DIR / "rules").as_posix(),
                         str(target), str(out_file), target.is_dir(), min_severity)
    try:
        # capture_output keeps Hayabusa's banner off the JSON-RPC stdout channel.
        return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              cwd=tmpdir, timeout=TIMEOUT_SECONDS), "windows"
    except OSError as exc:
        if getattr(exc, "winerror", None) != APP_CONTROL_WINERROR:
            raise ToolError(f"Could not run Hayabusa: {exc}") from exc

    wsl_binary = find_wsl_binary()
    rules = wsl_binary.rsplit("/", 1)[0] + "/rules"
    argv = ["wsl.exe", "--cd", to_wsl_path(tmpdir), "-e"] + hayabusa_args(
        wsl_binary, rules, to_wsl_path(target), to_wsl_path(out_file),
        target.is_dir(), min_severity)
    return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                          timeout=TIMEOUT_SECONDS), "wsl"


def normalize_level(value: Any) -> str | None:
    """Hayabusa abbreviates levels in output (`info`, `med`, `crit`)."""
    text = str(value).strip().lower()
    matches = [name for name in SEVERITY_ORDER if name.startswith(text)]
    return matches[0] if text and len(matches) == 1 else None


@server.tool()
def scan_evtx(
    path: Annotated[str, Field(
        description="Path to a single .evtx file, or a directory containing them.",
    )],
    min_severity: Annotated[Severity, Field(
        description="Lowest severity to report. Defaults to 'informational' (everything).",
    )] = "informational",
) -> dict[str, Any]:
    """Scan a Windows EVTX file, or a directory of them, with Hayabusa and
    return the detections as structured JSON, filtered by minimum severity.
    """
    # 1. Verify the file exists.
    # Absolute: Hayabusa runs with a temp-dir cwd, so a relative path would miss.
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise ToolError(f"No such file or directory: {path}")

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        out_file = tmpdir / "timeline.jsonl"

        # 2. Run Hayabusa with JSONL output.
        try:
            proc, backend = run_hayabusa(target, out_file, tmpdir, min_severity)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Hayabusa timed out after {TIMEOUT_SECONDS}s") from exc

        # 5. Scan failures.
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).replace("\x00", "").strip()[-500:]
            raise ToolError(f"Hayabusa exited {proc.returncode}: {detail}")
        lines = out_file.read_text(encoding="utf-8").splitlines() if out_file.exists() else []
        # A corrupt EVTX still exits 0, but leaves an error log behind.
        error_logs = [p.read_text(errors="replace") for p in tmpdir.glob("logs/errorlog-*.log")]

    # 3. Filter by min_severity. Unknown levels are kept rather than dropped.
    floor = SEVERITY_ORDER.index(min_severity)
    findings = []
    for line in filter(str.strip, lines):
        finding = json.loads(line)
        level = normalize_level(finding.get("Level", ""))
        if level is None or SEVERITY_ORDER.index(level) >= floor:
            findings.append(finding)

    # 4. Return structured JSON.
    counts: dict[str, int] = {}
    for f in findings:
        key = normalize_level(f.get("Level", "")) or "unknown"
        counts[key] = counts.get(key, 0) + 1
    warnings = []
    if error_logs:
        warnings.append("Hayabusa reported errors -- a zero-finding result may not "
                        "mean the log is clean: " + error_logs[0].strip()[:1000])
    return {
        "target": str(target),
        "backend": backend,
        "min_severity": min_severity,
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "warnings": warnings,
    }


def main() -> None:
    # stdio transport: stdout IS the JSON-RPC channel. Never print() from
    # server code -- it corrupts the protocol frame. Log to stderr instead.
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
