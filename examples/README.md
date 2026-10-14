# Example output

Generated with Hayabusa v4.1.0 against the 20 default samples from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(`python scripts/fetch_samples.py`). Host and user names in the scan output
(`IEWIN7`, `IEUser`, ...) come from that public dataset.

| File | What it is |
|---|---|
| `scan_samples_summary.json` | `scan_evtx("samples")` with the default `output_format="summary"`: 261 events, 229 findings (24 high, 22 medium, 34 low, 149 informational). A per-rule `rules` rollup plus one slim row per finding, including the source EVTX file. |
| `credential_access_rules.by_technique.json` | The 291 enabled Hayabusa rules tagged `attack.credential-access`, as a tree: MITRE technique -> level -> rule titles. A rule tagged with several techniques appears under each. |
| `credential_access_rules.slim.json` | The same 291 rules as a flat list of `{title, level, techniques}`. |

## Viewing as a graph with JSON Crack

- **Web:** open <https://jsoncrack.com/editor> and paste the file contents into
  the editor pane (or use the editor's import option). The graph renders on the right.
- **VS Code:** install the *JSON Crack* extension, open one of these files, and
  run the JSON Crack command from the command palette or the editor title bar.

Tips:

- Start with `credential_access_rules.by_technique.json` and collapse
  everything except the technique you care about (e.g. `T1003.001` for LSASS).
- For scan results, the `rules` array in `scan_samples_summary.json` is the
  readable part; the `findings` array is one node per detection.
- For your own investigations, prefer the VS Code extension: real scan output
  contains host names, user names, command lines and hashes.
