# mcp-hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) so an MCP client can analyze Windows EVTX event logs and get structured results back.

Hayabusa is a Sigma-based threat hunting and forensics timeline generator. This server exposes it as a single tool, `scan_evtx`, and returns detections as JSON rather than CLI text — so a client can filter, count, and reason over them.

## Requirements

- Python 3.10+
- Hayabusa (installed by a script below — not vendored, not a pip package)
- WSL2 **if** Windows Application Control blocks the Hayabusa binary — see [Backends](#backends)

## Setup

```bash
pip install -r requirements.txt            # runtime: mcp
pip install -r requirements-dev.txt        # plus pytest

python scripts/fetch_hayabusa.py           # Hayabusa release -> ./hayabusa/
python scripts/fetch_samples.py            # optional: test EVTX files -> ./samples/
```

`fetch_hayabusa.py` resolves the right release asset for your platform from the GitHub API and unpacks it. The binary's name carries its version and platform (`hayabusa-4.1.0-win-x64.exe`), so the script records the resolved name in `hayabusa/.hayabusa-release.json` and the server reads it from there — nothing hardcodes a filename.

`fetch_samples.py` pulls EVTX captures from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (ATT&CK-mapped attack simulations) — two per category by default, ~1.4 MB. Use `--all` for all 278 (~49 MB). These are log files, not live malware.

Neither `hayabusa/` nor `samples/` is tracked in git; both are setup-time downloads.

## Registering with Claude Code

`.mcp.json` declares the server and `.claude/settings.json` pre-approves it, so a restart is all it takes:

```jsonc
// .mcp.json
{ "mcpServers": { "hayabusa": { "type": "stdio", "command": "python", "args": ["server.py"] } } }
```

Check with `/mcp`. Running `python server.py` by hand is valid but blocks silently on stdin — it's a stdio server waiting for a client, not a hang.

## The `scan_evtx` tool

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `path` | string | *required* | A single `.evtx` file, or a directory of them |
| `min_severity` | enum | `informational` | `informational` · `low` · `medium` · `high` · `critical` · `emergency` |

Response:

```json
{
  "target": "C:\\...\\samples",
  "backend": "wsl",
  "min_severity": "high",
  "events_scanned": 261,
  "events_with_hits": 148,
  "finding_count": 24,
  "severity_counts": { "high": 24 },
  "findings": [ { "Timestamp": "...", "RuleTitle": "Important Log File Cleared", "Level": "high", "...": "..." } ],
  "truncated": false,
  "warnings": []
}
```

Findings are capped at 1000 with `truncated: true` set — never silently cut. `warnings` carries anything the caller should know: a backend fallback, unparsable output lines, or Hayabusa's own error log.

**One warning matters more than the others.** A corrupt or non-EVTX file makes Hayabusa exit `0` with zero findings — which would otherwise read as "nothing suspicious found". The server detects it (via Hayabusa's error log and a `Total events: 0` parse) and says so explicitly: *a zero-finding result here does NOT mean the log is clean.*

## Backends

Hayabusa runs through one of two backends, chosen at runtime:

- **`windows`** — the native binary in `./hayabusa/`
- **`wsl`** — a Linux build inside WSL2, via `wsl.exe`

The default `auto` tries native first and falls back to WSL **only** when Windows Application Control refuses to execute the unsigned binary (`OSError` / `WinError 4551`). Native is tried first on purpose, so it resumes by itself if the policy is ever lifted. Force either with `MCP_HAYABUSA_BACKEND=windows|wsl`; the response always reports which one ran.

If you need the WSL backend, install the Linux build *inside* WSL:

```bash
python3 scripts/fetch_hayabusa.py --dest ~/hayabusa    # selects lin-x64-gnu
```

Keep it on ext4 (`~/hayabusa`), not `/mnt/c` — Hayabusa loads ~2,400 rule files per scan, and that many small reads over the 9p mount is much slower. Only the EVTX file and the JSONL output cross the boundary. Overrides: `MCP_HAYABUSA_WSL_DIR`, `MCP_HAYABUSA_WSL_DISTRO`.

Note that Smart App Control cannot be re-enabled once turned off without reinstalling Windows. Using WSL avoids that trade entirely.

## Tests

```bash
pytest                                 # both suites, ~50s
python tests/test_server_stdio.py      # or run either directly
python tests/test_scan_samples.py      # prints a summary report in this mode
```

- **`test_server_stdio.py`** — spawns the server as a subprocess and drives it with a real MCP client: handshake, tool listing, input schema, error paths, severity normalization, WSL path mapping, backend selection. Fixture-free, so it runs anywhere.
- **`test_scan_samples.py`** — imports the server in-process and scans `./samples/` for real. Skips with a fetch instruction if the samples aren't present.

Current baseline across the 20 default samples: **261 events, 229 findings** — 24 high, 22 medium, 34 low, 149 informational.

## Notes

Two details that cost real debugging time and are easy to get wrong:

- **Hayabusa abbreviates severity in JSON output** — findings come back as `info`, `med`, `crit`, not the full names. Ranking only the full names silently mis-sorts them, and an unranked `emer` under a `critical` floor would drop the most severe findings there are. `normalize_level()` resolves by unique prefix.
- **There is no `json-timeline` subcommand** in Hayabusa 4.x — it was folded into `dfir-timeline`. The equivalent is `--output-type jsonl`, written to a file; JSON on stdout is interleaved with the ASCII-art banner and progress text.

[CLAUDE.md](CLAUDE.md) documents the verified Hayabusa CLI behavior, the MCP SDK 2.x differences (`FastMCP` is `MCPServer` in 2.x), and the WSL gotchas in full.

## License

Hayabusa and the EVTX samples are the property of their respective authors and carry their own licenses.
