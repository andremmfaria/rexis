
## Baseline pipeline: end-to-end workflow (decompile -> heuristics -> optional VT -> decision -> report)

This guide explains the Baseline analysis workflow in detail: what it does, how to run it, what files it produces, how scores and labels are computed, and where each step is implemented.

Key entry points in the codebase:
- CLI command definition: `../src/rexis/cli/analyse_commands.py` (function `cmd_analyze_baseline`)
- Orchestrator: `../src/rexis/operations/baseline.py` (functions `analyze_baseline_exec`, `_process_sample`)
- Decompiler pipeline (PyGhidra): `../src/rexis/operations/decompile/main.py`
- Heuristics engine: `../src/rexis/tools/heuristics_analyser/main.py` (+ helpers in `utils.py`, `normal.py`)
- VirusTotal client: `../src/rexis/tools/virus_total.py`
- Decision fusion (heuristics + VT): `../src/rexis/tools/reconciliation/main.py`
- Defaults and thresholds: `../src/rexis/utils/constants.py`
- Settings (API keys, etc.): `../config/settings.toml`


## What the Baseline pipeline does

For each input PE binary (.exe/.dll/.sys):
1) Decompile and extract features with Ghidra via PyGhidra
2) Run built-in heuristic rules over the extracted features -> score, label, evidence, tags
3) Optionally enrich with VirusTotal (VT) by SHA-256
4) Fuse the heuristic signal with the VT signal into a final decision (score + label)
5) Emit JSON artifacts per sample and per-run summaries

Single-file mode produces one final `...report.json`. Directory mode discovers PE files recursively and processes them (optionally in parallel), plus a batch summary.


## How to run

CLI entrypoint: `rexis analyse baseline` (Typer-based, see `../src/rexis/cli/main.py`). Example invocations:
- Single file:
	- `pdm run rexis analyse baseline -i ./data/samples/<file>.exe -o ./data/analysis`
- Directory (recursive):
	- `pdm run rexis analyse baseline -i ./data/samples -o ./data/analysis --parallel 4`

Important options (from `cmd_analyze_baseline` in `../src/rexis/cli/analyse_commands.py`):
- `--input, -i` Path to a file or directory (required)
- `--out-dir, -o` Output root directory (defaults to current working directory)
- `--run-name, -r` Optional logical run name (defaults to a random UUID)
- `--overwrite, -y` Overwrite existing artifacts
- `--format, -f` Report format (currently only `json`)
- Ghidra/decompiler:
	- `--project-dir, -d` Ghidra projects store (default `~/.rexis/ghidra_projects`)
	- `--parallel, -p` Parallel worker count when input is a directory
- Heuristics:
	- `--rules` Path to rules config (YAML or JSON)
	- `--min-severity, -m` Evidence filter for output: `info|warn|error`
- VirusTotal enrichment:
	- `--vt` Enable VT lookup by SHA-256
	- `--vt-timeout` Timeout seconds (captured in run report; actual HTTP is via the `vt` SDK)
	- `--vt-qpm` Queries-per-minute budget (best-effort rate limiting)
- Logging/audit:
	- `--audit/--no-audit` Include an audit trail of pipeline events in reports


## Output layout and artifacts

Every run creates a per-run directory under the chosen `--out-dir`:
- Run directory: `baseline-analysis-<RUN_ID>/`
- For each input file with SHA-256 `H`:
	- Decompiler features: `baseline-analysis-<RUN_ID>/decompile-<RUN_ID>/H.features.json`
	- Heuristics result: `baseline-analysis-<RUN_ID>/H.baseline.json`
	- Final report (heuristics + VT + fusion): `baseline-analysis-<RUN_ID>/H.report.json`
- If the input is a directory, a batch summary is also written:
	- `baseline-analysis-<RUN_ID>/baseline_summary.json` (lists all per-file report paths)
- Per-run report (status, parameters, timing):
	- `baseline-analysis-<RUN_ID>/baseline-analysis-<RUN_ID>.report.json`

Notes:
- File discovery for directories looks for extensions `.exe`, `.dll`, `.sys` recursively (`iter_pe_files` in `../src/rexis/utils/utils.py`).
- If a worker fails on a file, a minimal `*.error.report.json` is emitted and included in the batch summary.


## Step 1 — Decompilation and feature extraction

Implementation: `../src/rexis/operations/decompile/main.py`
- Requires Ghidra installed at `/opt/ghidra` (enforced by `require_ghidra_env` in `../src/rexis/operations/decompile/utils.py`). See setup guide `./InstallGhidra.md`.
- Starts a JVM via PyGhidra, opens/creates a reusable Ghidra project in `--project-dir`.
- Waits for analysis, then collects:
	- Program info (name, format, language, compiler, image_base, size, sha256)
	- Functions, imports, strings, sections, libraries, exports, entry points
	- Decompiles functions (best-effort, per-function timeout)
- Writes features JSON to `decompile-<RUN_ID>/<sha256>.features.json` and a run-level decompile report.

In the baseline orchestrator (`_process_sample` in `../src/rexis/operations/baseline.py`):
- The features JSON is loaded.
- SHA-256 is extracted from `features.program.sha256` (or derived from the filename as a fallback).


## Step 2 — Heuristics scoring and tagging

Implementation: `../src/rexis/tools/heuristics_analyser/main.py`
- Applies a suite of built-in rules (see `rules.py` and helpers in `utils.py`), e.g.:
    - Suspicious API combinations, packer artifacts, tiny .text, low-entropy strings, writable entry section, networking indicators, HTTP exfil indicators, crypto usage, dynamic API resolution, shell execution, autorun/service persistence, filesystem modification, suspicious URLs, anti-VM, anti-debug, suspicious function names.
- Each rule can emit an Evidence item: `{id, title, detail, severity, score}`.
- Evidence now also records:
	- `reason`: short human-readable hit explanation when available
	- `categories`: top tags relevant to this evidence with per-tag scores
- Evidence set is combined into a score using a configurable strategy:
	- Default is weighted sum with per-rule caps (`weights`) and optional `base` contribution.
	- Label is assigned by thresholds (`malicious`, `suspicious`), with optional per-rule label overrides.
- Evidence filtering: `--min-severity` controls which evidence is returned in the report, but the score uses the full evidence set.
- Tagging: evidence is mapped to canonical tags with weights; tags below threshold are dropped after ranking.

Configuration knobs and defaults (see `../src/rexis/utils/constants.py` and loader `load_heuristic_rules` in `../src/rexis/tools/heuristics_analyser/utils.py`):
- If `--rules` is omitted, `DEFAULT_HEURISTIC_RULES` are used.
- A rules file (YAML or JSON) may override:
    - `scoring`: `base`, `combine` (`weighted_sum|max`), `label_thresholds.{malicious,suspicious}`
    - `weights`: per-rule weight caps
    - `allow_rules` / `deny_rules`: enable/disable subsets of rules
    - `label_overrides`: map certain rule hits directly to labels
    - `rule_args`: per-rule tuples `(score, {params})` to adjust rule weight and parameters
    - `tagging`: `map`, `tag_weights`, `threshold`, `top_k`, `classification_top_k`, `evidence_top_k`
    - `taxonomy.normalization_rules`: regex-to-family mapping for VT name normalization (used later)

Heuristics output shape (subset):
- `schema`: `rexis.baseline.heuristics.v1`
- `score`: float in [0,1]
- `label`: `malicious|suspicious|benign`
- `evidence`: filtered by `--min-severity`, each item may include `reason` and `categories`
- `counts`: evidence counts by severity
- `tags`: ranked tag list with scores
- `classification`: list of top tags (names) used as a light-weight heuristic classification summary
- `rule_misses`: non-hit reasons per rule


## Step 3 — Optional VirusTotal enrichment

Implementation: `_vt_enrich_sha256` in `../src/rexis/operations/baseline.py` and client in `../src/rexis/tools/virus_total.py`.
- Opt-in via `--vt` and an API key in `../config/settings.toml` under `[baseline].virus_total_api_key`.
- Looks up the sample by SHA-256 using the `vt` Python SDK (VT v3 API).
- Returns a compacted record with useful attributes (size, names/tags/type info, meaningful name, last analysis stats, popular_threat_* fields, first/last submission dates).
- Best-effort QPM rate limiting is applied via `wait_qpm` in `../src/rexis/utils/utils.py`. Note: in parallel mode the limit is per-process (not centrally coordinated).
- Errors are captured and included in the final report.


## Step 4 — Decision fusion (heuristics ⊕ VT)

Implementation: `fuse_heuristics_and_virustotal_decision` in `../src/rexis/tools/reconciliation/main.py`.
- Signals:
	- Heuristics score (Sh) and a derived confidence (Ch)
	- VT score (Svt) and a derived confidence (Cvt) (or `not_available` if VT failed/disabled)
- Fused score: `w_h * Ch * Sh + w_vt * Cvt * Svt`, then disagreement penalty if both signals exist and diverge.
- Conflict override: if both confidences are high and the gap is large, force a mid score and abstain/suspicious label based on policy.
- Label is then chosen by thresholds.

Configuration sources:
- Defaults for the fusion are in `DEFAULT_DECISION` (`../src/rexis/utils/constants.py`).
- The heuristics rules file may optionally include a `decision.*` section to override:
    - `decision.weights` -> `{w_h, w_vt}`
    - `decision.thresholds` -> `{malicious, suspicious}`
    - `decision.policy` -> keys like `gap_penalty_start`, `gap_penalty_max`, `gap_penalty_slope`, `conflict_gap_hard`, `high_conf`, `conflict_override_score`, `abstain_on_conflict`, `heuristics_conf`, `cat_map`, `C_h_floor`, `C_h_ceil`, `C_vt_floor`, `C_vt_ceil`, and more supported by `ReconcileConfig`.

Decision output shape (subset, embedded under `decision` in the final report):
- `inputs.{heuristics,virustotal}` compact summaries
- `confidence.{heuristics_confidence, virustotal_confidence}`
- `weights.{heuristics_weight, virustotal_weight}`
- `comparison.{score_gap, disagreement_penalty, conflict_override_applied}`
- `final.{score, label, thresholds, decision_thresholds}`
- `explanation`: human-readable notes


## Step 5 — Final report and audit trail

The per-sample final report (`H.report.json`) includes:
- `schema`: `rexis.baseline.report.v1`
- `run_id`, `generated_at`, `duration_sec`
- `sample`: `{sha256, source_path}`
- `artifacts`: paths to features and heuristics JSONs
- `program`: basic program info from decompiler
- `taxonomy`:
	- `families`: counts derived from VT “popular threat name/category” and `meaningful_name`, normalized via regex rules in the heuristics config (or defaults in `DEFAULT_NORMALIZATION_RULES` from `../src/rexis/utils/constants.py`). Implementation in `../src/rexis/tools/heuristics_analyser/normal.py`.
	- `tags`: top tags inferred from heuristics evidence
- `classification`: `{heuristics: [..], virustotal: [..]}` — top heuristic tags and VT-derived families/names
- `final`: shortcut to fused `score` and `label`
- `decision`: full fusion object
- `heuristics`: full heuristics object
- `virus_total`: `{data, error}` when VT was enabled
- `audit`: chronological events if `--audit` is enabled (default on)

Audit events (emitted by `_process_sample`):
- `pipeline_start` -> input file and run id
- `decompile_start` / `decompile_done`
- `heuristics_start` / `heuristics_done`
- `vt_start` / `vt_done` (includes fields `ok` and `error`)
- `pipeline_done`

Per-run report (`baseline-analysis-<RUN_ID>.report.json`) captures:
- Timing, status, inputs (all CLI options), outputs (primary result, run dir, report list), and environment info like `rexis_version` and `project_dir`.


## Behavior differences: single-file vs directory

- Single file:
	- `analyze_baseline_exec` processes the file and returns the path to `H.report.json` as the primary output.
- Directory:
	- Files are discovered via `iter_pe_files`.
	- If `--parallel > 1`, files are processed with a `ProcessPoolExecutor`; otherwise sequentially.
	- A `baseline_summary.json` is generated listing each per-file report path.


## Prerequisites and environment

- Ghidra required at `/opt/ghidra`. See `./InstallGhidra.md`.
- VirusTotal (optional): set `[baseline].virus_total_api_key` in `../config/settings.toml` (key-value resolution is handled by the project’s config loader).
- Python dependencies: PyGhidra and `vt` are used by the decompiler and VT client respectively.


## Troubleshooting and notes

- Report format: only `json` is supported (`--format json`).
- VT timeout: the `--vt-timeout` option is recorded in run metadata; actual HTTP requests are performed by the `vt` SDK which doesn’t use this value directly.
- Rate limiting: `--vt-qpm` applies a simple sleep-based limiter; in parallel mode it’s per-process, not a shared limiter.
- Overwrite semantics: if the features JSON already exists and `--overwrite` is not set, the decompiler step will raise; set `-y` to regenerate.
- File extensions: adjust `iter_pe_files` in `../src/rexis/utils/utils.py` to support additional formats if needed.


## Quick reference: key files

- CLI: `../src/rexis/cli/analyse_commands.py`
- Orchestrator: `../src/rexis/operations/baseline.py`
- Decompiler: `../src/rexis/operations/decompile/main.py`
- Heuristics: `../src/rexis/tools/heuristics_analyser/main.py`
- VirusTotal: `../src/rexis/tools/virus_total.py`
- Decision fusion: `../src/rexis/tools/reconciliation/main.py`
- Defaults: `../src/rexis/utils/constants.py`
- Settings: `../config/settings.toml`
