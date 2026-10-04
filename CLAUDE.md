# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

`scan_evtx` is implemented and verified against real EVTX data. Not a git repository.

## Setup

```bash
pip install -r requirements.txt       # mcp 2.3.0 + transitive deps
pip install -r requirements-dev.txt   # the above plus pytest
python scripts/fetch_hayabusa.py      # Hayabusa release -> ./hayabusa/
python server.py                      # stdio server; waits for an MCP client on stdin (not interactive)
python scripts/fetch_samples.py       # attack-sample EVTX files -> ./samples/
pytest                                # both suites (~12s)
```

`fetch_hayabusa.py` resolves the right release asset for the host platform from the GitHub API and unpacks it. Useful flags: `--tag v4.1.0` to pin a release, `--force` to replace an existing `./hayabusa/`, `--platform <slug>` to override detection, `--dest` to extract elsewhere. Set `GITHUB_TOKEN` if you hit the unauthenticated 60-requests/hour API limit.

Environment as of 2026-10-04: Python 3.14.5, pip 26.1.1. `mcp` 2.3.0 is installed into the **user-level system Python** (no virtualenv). Hayabusa v4.1.0 is installed at `hayabusa/hayabusa-4.1.0-win-x64.exe` (5,080 rules, 11 config files); it is *not* on PATH, so invoke it by path.

## Registering with Claude Code

MCP servers are **defined in `.mcp.json`, not `.claude/settings.json`** — the settings schema has no key for declaring one. The two files do different jobs:

- **`.mcp.json`** declares the server: `hayabusa`, `python server.py`, stdio. `args` is relative, so Claude Code must launch it with the project root as cwd. If it fails to start, switch to absolute paths for both the interpreter and the script.
- **`.claude/settings.json`** carries `enabledMcpjsonServers: ["hayabusa"]`, which pre-approves it so the trust prompt is skipped. (`enableAllProjectMcpServers: true` would approve every entry instead.)

`.claude/settings.json` is committed; `.claude/settings.local.json` is gitignored for personal overrides. Changes to either need a Claude Code restart; check with `/mcp`.

## Tests

`pytest` from the project root runs both suites in ~12s (6 tests). `pytest.ini` sets `testpaths = tests` and `pythonpath = .`. Each file also runs standalone with `python tests/<file>.py` — the test functions are sync and own their event loop, so no async plugin is needed, and `test_scan_samples.py` prints a summary report in that mode. pytest lives in `requirements-dev.txt`, not `requirements.txt`.

- **`tests/test_server_stdio.py`** — spawns `server.py` as a subprocess and drives it with a real MCP client: handshake, tool listing, input schema, error paths, level normalization. Deliberately **fixture-free**, so it runs anywhere.
- **`tests/test_scan_samples.py`** — imports `server.py` in-process and scans real attack samples from `./samples/`. Skips (3 tests) with a fetch instruction if the samples are absent, so a fresh clone passes.

`scripts/fetch_samples.py` pulls EVTX captures from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (ATT&CK-mapped attack simulations) into `./samples/` — 2 per category by default (~1.4 MB), `--all` for all 278 (~49 MB). Files are chosen by rule (smallest N per category), not a hardcoded list, so it survives upstream changes; a magic-byte check rejects anything that isn't really an EVTX.

Current baseline: the 20 default samples yield **261 events, 229 findings** (24 high, 22 medium, 34 low, 149 informational, 0 critical). Run it directly (`python tests/test_server_stdio.py`, prints `ok:` and exits 0) or under pytest — the test function is sync and owns its event loop, so no async plugin is needed.

Two conventions worth keeping if you add tests:

- **Assert outside the anyio task group.** Gather facts inside the `stdio_client` / `ClientSession` context and assert after it exits; an `AssertionError` raised inside comes back wrapped in nested `ExceptionGroup`s that hide which assertion failed.
- **Test through a client session, not `server.call_tool()`.** The in-process call skips `main()` and the transport, and it *raises* `ToolError` where a real session returns `is_error=True`.

## How scan_evtx runs Hayabusa

Verified against v4.1.0 — re-check if the version changes.

- **There is no `json-timeline` subcommand.** It existed in Hayabusa 2.x and was folded into `dfir-timeline`. The equivalent is `dfir-timeline --output-type jsonl`.
- **`--no-wizard` is mandatory.** Without it Hayabusa asks questions interactively and the subprocess hangs forever.
- **JSON on stdout is interleaved with the banner and progress text**, and ANSI resets survive `--no-color`. Always write results with `--output <file>` and read the file; never parse stdout for findings.
- **`capture_output=True` is load-bearing.** Inherited stdout would put Hayabusa's ASCII-art banner on the JSON-RPC channel and kill the session.
- **Run with `cwd` set to a temp dir and pass `--rules`/`--rules-config` as absolute paths.** Their defaults (`./rules`, `./rules/config`) are relative to cwd, so they break when a client launches the server from elsewhere. The temp cwd also keeps Hayabusa's `logs/errorlog-*.log` out of the project.
- **A corrupt EVTX exits 0.** It produces zero findings, a ~1-byte output file, and an error log — reported naively that reads as "nothing found". Detect it by globbing `logs/errorlog-*.log` in the temp cwd and by parsing `Events with hits / Total events` from stdout; `0` total events on an existing file means nothing was scanned.

### Severity levels

Canonical levels, lowest to highest: `informational`, `low`, `medium`, `high`, `critical`, `emergency`. `--min-level --help` lists only the first five, but the CLI accepts `emergency` and `config/level_color.txt` lists it.

**Hayabusa abbreviates levels in JSON output** — findings come back as `info`, `med`, `crit`, not the full names. Ranking only the full names silently mis-sorts them, and an unranked `emer` under a `critical` floor would drop the most severe findings there are. `normalize_level()` resolves by unique prefix, so abbreviations and full names both work.

## Hayabusa release layout

Release archives have **no wrapper directory** — they unpack `config/`, `rules/`, and the executable straight into the destination. The executable name carries the version and platform (`hayabusa/hayabusa-4.1.0-win-x64.exe`), so **never hardcode it**. `fetch_hayabusa.py` writes `hayabusa/.hayabusa-release.json` with the resolved relative path under `binary`; read that to locate the executable.

Asset names follow `hayabusa-<version>-<platform>.zip`, with platform slugs `win-x64`, `win-x86`, `win-aarch64`, `mac-x64`, `mac-aarch64`, and `lin-{x64,aarch64}-{gnu,musl}`. Match asset names by **exact equality** — a substring test for `win-x64` also matches the cut-down `win-x64-live-response.zip` build.

## MCP SDK 2.x API note

This is `mcp` 2.x, where `FastMCP` was **renamed to `MCPServer`**. Use:

```python
from mcp.server.mcpserver import MCPServer
```

`mcp.server.fastmcp` does not exist and raises `ModuleNotFoundError` pointing at the migration guide. Most `FastMCP` examples online are v1 — translate them rather than copying. Migration guide: https://py.sdk.modelcontextprotocol.io/v2/migration/

Other 2.x differences, all verified against 2.3.0:

- **Model fields are `snake_case`**, not the wire protocol's camelCase: `tool.input_schema`, `result.is_error`, `init.server_info`, `init.protocol_version`. v1 used camelCase, so copied v1 client code fails with `AttributeError`.
- `ToolError` is at `mcp.server.mcpserver.exceptions`, not the package root.
- `server.run(transport="stdio")` is **synchronous** — `main()` needs no `asyncio.run`. The async forms are `run_stdio_async()` / `run_streamable_http_async()`.
- Tool functions may be sync; the SDK runs them in a worker thread.
- Calling `server.call_tool(...)` directly **raises** `ToolError`. Over a real client session the same failure arrives as a result with `is_error=True`. Test error handling through a client session, not the direct call.
- A `Literal[...]` annotation becomes a JSON Schema `enum`, so invalid values are rejected by validation before the function runs.
- Passing `description=` to `@server.tool()` **overrides the docstring**, and param docs in a docstring `Args:` block do *not* reach the schema. Describe parameters with `Annotated[T, Field(description=...)]`.
- On stdio, **stdout is the JSON-RPC channel**. A stray `print()` anywhere in the server process corrupts the protocol frame — send diagnostics to stderr.

## What this project is

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) so an MCP client can analyze Windows EVTX event logs.

## Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON (not raw CLI text)
- Support filtering by severity level
- Handle errors gracefully — surface Hayabusa failures as useful tool errors rather than crashing the server

## Stack

- **Python**, using the `mcp` library for the server implementation
- **Hayabusa CLI**, installed locally — invoked as an external subprocess; it is not vendored or reimplemented

## Notes for implementation

Verified against the installed v4.1.0 binary — re-check with `hayabusa help <command>` if the version changes:

- There is **no `--version` flag**; use `hayabusa help` to confirm the binary runs.
- The subcommand backing `scan_evtx` is **`dfir-timeline`**. Input: `-f/--file <FILE>` for one EVTX, `-d/--directory <DIR>` for many.
- JSON output: `-t/--output-type json|jsonl` (default is `csv`), with `-o/--output <FILE>` to write to a file. Prefer `jsonl` for streaming/large results.
- Severity filtering: `-m/--min-level <LEVEL>` (floor) or `-e/--exact-level <LEVEL>`. Levels are `informational`, `low`, `medium`, `high`, `critical`; the default minimum is `informational`.
- Timestamps default to local time — pass `-U/--utc` or `-O/--iso-8601` for machine-readable output.
