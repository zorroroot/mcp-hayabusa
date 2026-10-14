#!/usr/bin/env python3
"""MCP server exposing Hayabusa EVTX analysis.

Written against mcp 2.x, where the server class is `MCPServer` (v1's `FastMCP`
was renamed).

Hayabusa runs through one of two backends, chosen at runtime:

* `windows` -- the native binary in ./hayabusa/
* `wsl`     -- a Linux build inside WSL2, reached via wsl.exe

The default (`auto`) tries native first and falls back to WSL when Windows
Application Control blocks the unsigned executable (WinError 4551). That means
the native path resumes automatically if the policy is ever lifted. Force one
with MCP_HAYABUSA_BACKEND=windows|wsl.

This is a stdio server: run directly it blocks on stdin and prints nothing,
which is correct, not a hang. An MCP client spawns it and speaks JSON-RPC over
the pipe. To exercise it locally:

    python tests/test_server_stdio.py
"""

from __future__ import annotations

import json
import os
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

# scan_evtx paths come from the model, so they can come from a prompt or from
# text inside the logs being analyzed. Only these roots may be scanned:
# MCP_HAYABUSA_ALLOWED_ROOTS, os.pathsep-separated (`;` on Windows), or `*`
# to allow any path. Unset, it is just ./samples -- secure by default.
DEFAULT_ALLOWED_ROOT = Path(__file__).parent / "samples"

# Windows Application Control (Smart App Control / WDAC) refusing to execute an
# unsigned binary. Surfaces as OSError with this .winerror -- the trigger for
# falling back to WSL.
APP_CONTROL_WINERROR = 4551

# Where the Linux build lives inside WSL. Keep the binary and its ~2,400 rule
# files on ext4: loading them over the /mnt/c 9p mount is far slower.
WSL_DIR = os.environ.get("MCP_HAYABUSA_WSL_DIR", "~/hayabusa")

# A full scan loads ~2,400 rules and can run for minutes on a large EVTX.
# Unbounded, a hung scan would wedge the server with no way for the client out.
SCAN_TIMEOUT_SECONDS = 900

# Findings are returned inline to a model; a noisy scan can produce tens of
# thousands. Cap the payload and report the cap rather than truncating silently.
MAX_FINDINGS = 1000

OutputFormat = Literal["summary", "full"]

# Fields kept per finding in `summary` output. `Details` and `ExtraFieldInfo`
# are most of the payload; a full scan of the samples is ~165 KB with them.
SUMMARY_FIELDS = (
    "Timestamp", "RuleTitle", "Level", "Computer", "Channel",
    "EventID", "RecordID", "EvtxFile",
)

# Hayabusa abbreviates MITRE tactics in output (`LatMov`, `CredAccess`), just as
# it abbreviates levels -- a substring match for "lateral" against the raw
# value finds nothing. Expansions from config/mitre_tactics.txt (v4.1.0);
# hardcoded because under the WSL backend that file is inside the distro.
MITRE_TACTICS = {
    "Recon": "reconnaissance",
    "ResDev": "resource-development",
    "InitAccess": "initial-access",
    "Exec": "execution",
    "Persis": "persistence",
    "PrivEsc": "privilege-escalation",
    "Stealth": "stealth defense-evasion",
    "DefImpair": "defense-impairment",
    "CredAccess": "credential-access",
    "Disc": "discovery",
    "LatMov": "lateral-movement",
    "Collect": "collection",
    "C2": "command-and-control",
    "Exfil": "exfiltration",
    "Impact": "impact",
}

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
    """Resolve the native Hayabusa executable.

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


def to_wsl_path(path: str | Path) -> str:
    r"""Map a Windows path into WSL: C:\Users\x -> /mnt/c/Users/x.

    Only drive-letter paths can be mapped. A UNC path (\\server\share) has no
    /mnt equivalent, so it raises rather than producing a path that silently
    does not exist inside WSL.
    """
    resolved = Path(path).resolve()
    drive, rest = os.path.splitdrive(str(resolved))
    if not drive.endswith(":") or len(drive) != 2:
        raise ToolError(
            f"Cannot map {resolved} into WSL: expected a drive-letter path, "
            f"got {drive!r}. UNC and mapped network paths are not supported."
        )
    return f"/mnt/{drive[0].lower()}{rest.replace(os.sep, '/').replace(chr(92), '/')}"


def _wsl_prefix() -> list[str]:
    """wsl.exe invocation, optionally pinned to a distro."""
    cmd = ["wsl.exe"]
    distro = os.environ.get("MCP_HAYABUSA_WSL_DISTRO")
    if distro:
        cmd += ["-d", distro]
    return cmd


_wsl_cache: dict[str, tuple[str, str]] = {}


def wsl_hayabusa() -> tuple[str, str]:
    """Return (binary, rules_dir) as Linux paths, read from the WSL manifest.

    `WSL_DIR` may contain `~`, which only the Linux shell can expand, so this
    asks bash for the resolved directory and the manifest in one round trip.
    Cached: each call otherwise costs a distro round trip.
    """
    if WSL_DIR in _wsl_cache:
        return _wsl_cache[WSL_DIR]

    script = f'cd {WSL_DIR} && printf "%s\\n" "$PWD" && cat .hayabusa-release.json'
    try:
        proc = subprocess.run(
            _wsl_prefix() + ["-e", "bash", "-lc", script],
            capture_output=True, text=True, errors="replace", timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"Could not reach WSL: {exc}") from exc

    # wsl.exe emits UTF-16 on some paths; strip the NULs that leaves behind.
    out = (proc.stdout or "").replace("\x00", "").strip()
    if proc.returncode != 0 or not out:
        err = (proc.stderr or "").replace("\x00", "").strip()
        raise ToolError(
            f"Hayabusa is not installed in WSL at {WSL_DIR}. Inside WSL run: "
            f"python3 scripts/fetch_hayabusa.py --dest {WSL_DIR}"
            + (f" ({err})" if err else "")
        )

    directory, _, blob = out.partition("\n")
    try:
        binary = json.loads(blob)["binary"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise ToolError(f"Malformed manifest in WSL at {WSL_DIR}: {exc}") from exc

    directory = directory.strip().rstrip("/")
    resolved = (f"{directory}/{binary}", f"{directory}/rules")
    _wsl_cache[WSL_DIR] = resolved
    return resolved


def allowed_roots() -> list[Path] | None:
    """The roots scan_evtx may read under, or None for unrestricted (`*`).

    Read per call, like MCP_HAYABUSA_BACKEND, so tests can change it.
    """
    raw = os.environ.get("MCP_HAYABUSA_ALLOWED_ROOTS", "").strip()
    if raw == "*":
        return None
    if not raw:
        return [DEFAULT_ALLOWED_ROOT.resolve()]
    return [Path(p.strip()).expanduser().resolve()
            for p in raw.split(os.pathsep) if p.strip()]


def check_allowed(target: Path) -> None:
    """Raise ToolError unless `target` (already resolved) is under an allowed root.

    `target` must come from Path.resolve(), which collapses `..` and follows
    symlinks and junctions, so neither can step outside a root. Containment is
    by path components, not string prefix: `samples-evil` is not under
    `samples`. On Windows the comparison is case-insensitive, as the
    filesystem is.
    """
    roots = allowed_roots()
    if roots is None:
        return
    if any(target == root or root in target.parents for root in roots):
        return
    raise ToolError(
        f"{target} is outside the allowed scan roots: "
        f"{', '.join(str(r) for r in roots)}. To allow it, add its folder to "
        f"MCP_HAYABUSA_ALLOWED_ROOTS (separated by {os.pathsep!r}) in the "
        f"server's env config, or set it to * to allow any path."
    )


def _backend_order() -> list[str]:
    """Which backends to try, in order."""
    choice = os.environ.get("MCP_HAYABUSA_BACKEND", "auto").strip().lower() or "auto"
    if choice in ("windows", "wsl"):
        return [choice]
    if choice != "auto":
        raise ToolError(
            f"MCP_HAYABUSA_BACKEND must be auto, windows or wsl (got {choice!r})."
        )
    return ["windows", "wsl"] if os.name == "nt" else ["windows"]


def _build_argv(
    backend: str, target: Path, out_file: Path, tmpdir: Path, min_severity: str
) -> tuple[list[str], Path | None]:
    """Build the Hayabusa command line. Returns (argv, cwd_for_subprocess).

    For WSL the working directory is set by `wsl.exe --cd` instead, so the
    subprocess cwd is None. Either way Hayabusa's `logs/errorlog-*.log` lands in
    `tmpdir`, which is on the Windows side and readable by the caller.
    """
    if backend == "windows":
        binary = str(hayabusa_binary())
        rules = HAYABUSA_DIR / "rules"
        if not rules.is_dir():
            raise ToolError(
                f"Hayabusa rules directory is missing ({rules}). "
                f"Re-run: python scripts/fetch_hayabusa.py --force"
            )
        prefix: list[str] = []
        rules_dir, scan_target, output = str(rules), str(target), str(out_file)
        cwd: Path | None = tmpdir
    elif backend == "wsl":
        binary, rules_dir = wsl_hayabusa()
        prefix = _wsl_prefix() + ["--cd", to_wsl_path(tmpdir), "-e"]
        scan_target, output = to_wsl_path(target), to_wsl_path(out_file)
        cwd = None
    else:  # pragma: no cover - guarded by _backend_order
        raise ToolError(f"Unknown backend: {backend}")

    argv = prefix + [
        binary, "dfir-timeline",
        "--directory" if target.is_dir() else "--file", scan_target,
        "--output-type", "jsonl",
        "--output", output,
        "--min-level", min_severity,
        # The only profile that emits RuleFile, MitreTactics/Tags and EvtxFile,
        # which rule_filter matches on and which say where a finding came from.
        "--profile", "verbose",
        # Absolute: the defaults are ./rules and ./rules/config, relative to cwd.
        "--rules", rules_dir,
        "--rules-config", f"{rules_dir}/config" if backend == "wsl"
                          else str(Path(rules_dir) / "config"),
        "--no-wizard",   # otherwise it prompts and the subprocess hangs
        "--utc",         # timestamps are local time by default
        "--no-color",
        "--clobber",
    ]
    return argv, cwd


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


def _as_list(value: Any) -> list[str]:
    """A verbose-profile tag field: a list, a bare string, or absent when empty."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _fold(text: str) -> str:
    """Lowercase and treat `-`, `_` and spaces alike, so "lateral movement",
    "lateral-movement" and "lateral_movement" all match each other."""
    return re.sub(r"[-_\s]+", " ", text.lower()).strip()


def rule_matches(finding: dict[str, Any], term: str) -> bool:
    """Does `term` appear in this finding's rule metadata?

    Checks the rule title, rule file name, MITRE tactics (expanded from
    Hayabusa's abbreviations), MITRE technique tags and other tags.
    """
    tactics = _as_list(finding.get("MitreTactics"))
    haystack = [
        str(finding.get("RuleTitle", "")),
        str(finding.get("RuleFile", "")),
        *tactics,
        *(MITRE_TACTICS.get(t, "") for t in tactics),
        *_as_list(finding.get("MitreTags")),
        *_as_list(finding.get("OtherTags")),
    ]
    needle = _fold(term)
    return any(needle in _fold(field) for field in haystack)


def _basename(path: Any) -> str:
    """File name from either separator style: WSL reports /mnt/c/... paths."""
    return re.split(r"[\\/]", str(path))[-1]


def _slim(finding: dict[str, Any]) -> dict[str, Any]:
    """A `summary` row: SUMMARY_FIELDS only, with the EVTX path cut to its name."""
    row = {k: finding[k] for k in SUMMARY_FIELDS if k in finding}
    if "EvtxFile" in row:
        row["EvtxFile"] = _basename(row["EvtxFile"])
    return row


def _summarize_rules(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per rule: level, hit count, first/last time, where it fired."""
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        level = normalize_level(f.get("Level", "")) or "unknown"
        key = (str(f.get("RuleTitle", "")), level)
        ts = str(f.get("Timestamp", ""))
        row = rules.setdefault(key, {
            "rule_title": key[0], "level": level, "count": 0,
            "first_seen": ts, "last_seen": ts,
            "mitre_tactics": _as_list(f.get("MitreTactics")),
            "computers": set(), "evtx_files": set(),
        })
        row["count"] += 1
        row["first_seen"] = min(row["first_seen"], ts)
        row["last_seen"] = max(row["last_seen"], ts)
        if f.get("Computer"):
            row["computers"].add(str(f["Computer"]))
        if f.get("EvtxFile"):
            row["evtx_files"].add(_basename(f["EvtxFile"]))
    out = sorted(rules.values(),
                 key=lambda r: (-RANK.get(r["level"], len(RANK)), -r["count"]))
    for row in out:
        row["computers"] = sorted(row["computers"])
        row["evtx_files"] = sorted(row["evtx_files"])
    return out


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
        description=(
            "Absolute path to a single .evtx file, or a directory containing "
            "them. Must be under one of the server's allowed scan roots; the "
            "error for a disallowed path lists them."
        ),
    )],
    min_severity: Annotated[Severity, Field(
        description=(
            "Lowest severity to report. Defaults to 'informational', which "
            "reports everything."
        ),
    )] = "informational",
    rule_filter: Annotated[str | None, Field(
        description=(
            "Only report detections from rules whose title, rule file name, "
            "MITRE ATT&CK tactic or tag contains this text (case-insensitive), "
            "e.g. 'lateral', 'mimikatz', 'lsass', 'T1003'. All rules still run; "
            "this filters which detections are returned."
        ),
    )] = None,
    output_format: Annotated[OutputFormat, Field(
        description=(
            "'summary' (default): a per-rule rollup plus one slim row per "
            "detection (time, rule, level, computer, event ID, record ID, "
            "source file). 'full': every field Hayabusa reports, including "
            "Details and ExtraFieldInfo."
        ),
    )] = "summary",
    max_results: Annotated[int | None, Field(
        ge=1, le=MAX_FINDINGS,
        description=(
            f"Maximum number of detections to return (1-{MAX_FINDINGS}; default "
            f"{MAX_FINDINGS}). The most severe are kept. Counts always reflect "
            f"every matching detection."
        ),
    )] = None,
) -> dict[str, Any]:
    """Scan a Windows EVTX file, or a directory of them, with Hayabusa and
    return the detections as structured JSON. Optionally filter by minimum
    severity and by rule (title, MITRE tactic or tag), choose a compact
    summary or full detail, and limit how many detections come back.
    """
    limit = max_results or MAX_FINDINGS
    term = (rule_filter or "").strip()
    # Absolute: Hayabusa runs with a temp-dir cwd, so a relative path would miss.
    target = Path(path).expanduser().resolve()
    # Before the existence check, so the error does not reveal whether a path
    # outside the roots exists.
    check_allowed(target)
    if not target.exists():
        raise ToolError(f"No such file or directory: {path}")

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        out_file = tmpdir / "timeline.jsonl"

        proc = None
        backend = ""
        attempts: list[str] = []
        for kind in _backend_order():
            try:
                argv, cwd = _build_argv(kind, target, out_file, tmpdir, min_severity)
            except ToolError as exc:
                attempts.append(f"{kind}: {exc}")
                continue
            try:
                # capture_output is load-bearing: inherited stdout would put
                # Hayabusa's ASCII-art banner on the JSON-RPC channel.
                proc = subprocess.run(
                    argv, capture_output=True, text=True, errors="replace",
                    cwd=cwd, timeout=SCAN_TIMEOUT_SECONDS,
                )
                backend = kind
                break
            except subprocess.TimeoutExpired as exc:
                raise ToolError(
                    f"Hayabusa timed out after {SCAN_TIMEOUT_SECONDS}s "
                    f"scanning {target} via {kind}."
                ) from exc
            except OSError as exc:
                # WinError 4551 is Application Control blocking the unsigned
                # binary -- expected, and exactly why the WSL backend exists.
                attempts.append(f"{kind}: {exc}")
                continue

        if proc is None:
            raise ToolError("Could not run Hayabusa. Tried -- " + "; ".join(attempts))

        stdout = ANSI.sub("", proc.stdout or "").replace("\x00", "")
        stderr = ANSI.sub("", proc.stderr or "").replace("\x00", "").strip()

        if proc.returncode != 0:
            tail = stderr or " ".join(stdout.strip().splitlines()[-3:]) or "no output"
            raise ToolError(f"Hayabusa exited {proc.returncode} via {backend}: {tail}")

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
        if term and not rule_matches(finding, term):
            continue
        key = level or "unknown"
        counts[key] = counts.get(key, 0) + 1
        kept.append(finding)

    warnings: list[str] = []
    if attempts:
        warnings.append(f"Fell back to the {backend} backend: {'; '.join(attempts)}")
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

    # Over the limit, keep the most severe (unknown levels rank highest, as
    # they are never dropped). A plain head-of-list cut would return the
    # earliest informational noise and hide the highs.
    returned = kept
    if len(kept) > limit:
        def severity(f: dict[str, Any]) -> int:
            level = normalize_level(f.get("Level", ""))
            return RANK[level] if level else len(RANK)
        returned = sorted(kept, key=lambda f: -severity(f))[:limit]
    # Hayabusa orders a directory scan file by file, not globally by time.
    # `--utc` timestamps share one format, so they sort as strings.
    returned = sorted(returned, key=lambda f: str(f.get("Timestamp", "")))

    result: dict[str, Any] = {
        "target": str(target),
        "backend": backend,
        "min_severity": min_severity,
        "rule_filter": term or None,
        "output_format": output_format,
        "max_results": limit,
        "events_scanned": total,
        "events_with_hits": hits,
        "finding_count": len(kept),
        "severity_counts": {
            lvl: counts[lvl]
            for lvl in [*reversed(SEVERITY_ORDER), "unknown"]
            if lvl in counts
        },
    }
    if output_format == "summary":
        # The rollup covers every matching detection, not just those returned.
        result["rules"] = _summarize_rules(kept)
        result["findings"] = [_slim(f) for f in returned]
    else:
        result["findings"] = returned
    result["truncated"] = len(kept) > len(returned)
    result["warnings"] = warnings
    return result


def main() -> None:
    # stdio transport: stdout IS the JSON-RPC channel. Never print() from
    # server code -- it corrupts the protocol frame. Log to stderr instead.
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
