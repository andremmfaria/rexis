## LLM+RAG pipeline: end-to-end workflow (features -> hybrid retrieval -> re-rank -> LLM JSON -> report)

This document explains the LLM+RAG pipeline in detail: inputs, control knobs, retrieval and re-ranking internals, LLM classification schema, outputs, and where each piece lives in the repo.

Key code entry points:
- CLI command: `../src/rexis/cli/analyse_commands.py` (function `cmd_analyze_llmrag`)
- Orchestrator: `../src/rexis/operations/llmrag.py` (`analyze_llmrag_exec`, `_process_sample`)
- Decompiler (shared with baseline): `../src/rexis/operations/decompile/main.py`
- Retrieval: `../src/rexis/tools/retrieval/main.py`, `ranking.py`, `searches.py`, `store.py`
- LLM classification: `../src/rexis/tools/llm/main.py` (+ `messages.py`, `features.py`, `utils.py`)
- Shared constants/config: `../src/rexis/utils/constants.py`, `../config/settings.toml`


## What the LLM+RAG pipeline does

For each input sample, it ensures features exist (reuse `*.features.json` or decompile a PE), builds retrieval queries, performs hybrid retrieval (dense + keyword), optionally re-ranks with a cross-encoder LLM, then prompts a chat LLM to produce a strict JSON classification that includes score, label, classification tags (e.g., ransomware, trojan), families, capabilities, evidence, and uncertainty. It writes an `.llmrag.json` per sample and a final `.report.json` summarizing everything.


## How to run

CLI entrypoint: `rexis analyse llmrag`. Examples:
- Single file:
	- `pdm run rexis analyse llmrag --input ./data/samples/<file>.exe --out-dir ./data/analysis/llmrag`
- Directory (recursive over PE files):
	- `pdm run rexis analyse llmrag -i ./data/samples -o ./data/analysis/llmrag --parallel 4`

Options (from `cmd_analyze_llmrag` in `../src/rexis/cli/analyse_commands.py`):
- Input/output and run context:
	- `--input, -i` File or directory (required)
	- `--out-dir, -o` Output root (defaults to CWD)
	- `--run-name, -r` Optional run tag (defaults to UUID)
	- `--overwrite, -y` Overwrite existing artifacts
	- `--format, -f` Only `json` is supported
	- Ghidra project: `--project-dir, -d` (default `~/.rexis/ghidra_projects`)
	- Parallelism: `--parallel, -p` for directory mode
- Retrieval knobs:
	- `--top-k-dense, -td` Candidates per dense search (default 50)
	- `--top-k-keyword, -tk` Candidates per keyword search (default 50)
	- `--final-top-k, -fk` Passages fed to LLM after fuse/rerank (default 8)
	- `--join, -j` Fusion mode for dense+keyword: `rrf|merge` (default rrf)
	- `--rerank-top-k, -rk` If >0, listwise re-rank top K with a cross-encoder LLM
	- `--ranker-model, -rm` Model id for reranker (OpenAI chat generator)
	- `--source, -s` Repeatable filter to restrict retrieval to sources (e.g., `--source malpedia`)
- LLM generator knobs:
	- `--model, -m` Generator model id (OpenAI via Haystack)
	- `--temperature, -t` Sampling temperature
	- `--max-tokens, -mt` Max output tokens
	- `--seed, -sd` Randomness seed if supported
	- `--json-mode/--no-json-mode, -jm/--no-jm` Force JSON-only output
- Logging/audit:
	- `--audit/--no-audit, -a/--no-a` Include audit trail events in report


## Output layout and artifacts

Every run creates `llmrag-analysis-<RUN_ID>/` under `--out-dir`.
- If input is a PE file: features are produced or reused under `llmrag-analysis-<RUN_ID>/decompile-<RUN_ID>/`.
- Per-sample artifacts for SHA-256 `H`:
	- `H.llmrag.json` — model’s JSON classification
	- `H.report.json` — final report embedding the LLM output, retrieval notes, and audit
- Directory mode also creates: `llmrag_summary.json` (lists all per-file reports)
- Per-run report: `llmrag-analysis-<RUN_ID>/llmrag-analysis-<RUN_ID>.report.json`

File discovery: `.exe`, `.dll`, `.sys` recursively (`iter_pe_files` in `../src/rexis/utils/utils.py`). You may pass an existing `*.features.json` instead of a PE; it will be used directly.


## Step 1 — Ensure features (re-use or decompile)

Implementation: `_decompile_target` in `../src/rexis/operations/llmrag.py`.
- If the input ends with `.features.json`, it’s read as-is, and SHA-256 is inferred from filename or JSON.
- Else, it calls the shared decompiler (`../src/rexis/operations/decompile/main.py`) to produce features; see the Baseline guide for decompiler details and prerequisites (`./InstallGhidra.md`).


## Step 2 — Build retrieval queries from features

Implementation: `build_queries_from_features` in `../src/rexis/tools/retrieval/main.py`.
- Creates a compact set of query strings from imports, capability buckets, and program metadata.
- Capability buckets come from `CAPABILITY_BUCKETS` in `../src/rexis/utils/constants.py` (e.g., injection, persistence, network, crypto, anti_debug).
- Queries are capped (default 12) and are designed to work for both embedding and keyword retrieval.


## Step 3 — Hybrid retrieval (dense + keyword) with join and optional re-rank

Implementation: `retrieve_context` in `../src/rexis/tools/retrieval/main.py`.
- Initializes a PgVector document store via `init_store` (`../src/rexis/tools/retrieval/store.py`), configured with:
	- Connection string from `DATABASE_CONNECTION_CONNSTRING` (`../src/rexis/utils/constants.py`), which is built from `../config/settings.toml` `[db]`.
	- 1536-dim embeddings (OpenAI `text-embedding-3-small`), cosine similarity, HNSW search.
- Runs both:
	- Dense search using `OpenAITextEmbedder` and `PgvectorEmbeddingRetriever` (`searches.py`)
	- Keyword search using `PgvectorKeywordRetriever` (`searches.py`)
- Fuses results with Reciprocal Rank Fusion (`join_mode=rrf`) or simple merge, keeping best score per doc id.
- Optional re-rank when `rerank_top_k > 0`:
	- Uses OpenAI chat model as a listwise reranker (`ranking.py`), asks for strict JSON scores per `doc_id`.
	- Applies small authority bias by source (see `AUTH_BONUS` in `../src/rexis/utils/constants.py`) and diversification caps per source.
- Returns formatted passages for the LLM: `{doc_id, source, title, score, text}` plus `rag_notes` with metrics and settings.

Filters:
- `--source` builds a metadata filter like `{source: {$in: [...]}}` if provided.
- If the store fails to initialize or a retrieval step fails, the function logs and continues best-effort, returning empty or partial results with notes.


## Step 4 — LLM classification (JSON-only schema)

Implementation: `llm_classify` in `../src/rexis/tools/llm/main.py`.
- Summarizes features (`features.py`) into a compact payload (program info, imports-by-capability, packer hints, sections summary).
- Compacts passages to ≤8 items (truncate content) for prompt efficiency (`messages.py`).
- Builds a system message that demands STRICT JSON only with a fixed schema, and a user message containing the summarized features and retrieved passages.
- Calls OpenAI via Haystack `OpenAIChatGenerator` with `config.models.openai.api_key` and chosen `--model`.
- Parses reply strictly as JSON; if that fails, attempts a best-effort repair. On failure, returns a safe fallback result with `label=unknown` and `_debug.error`.
- Validates and normalizes the object into the schema:
	- `schema`: `rexis.llmrag.classification.v1`
	- `score`: [0,1], coerced
	- `label`: `malicious|suspicious|benign|unknown` coerced with thresholds from `../src/rexis/utils/constants.py`
	- `classification`: list of high-level malware tags (e.g., ransomware, trojan, worm), bounded length
	- `families`, `capabilities`, `tactics`: bounded lists
	- `evidence`: up to 8 items `{id,title,detail,severity,source,doc_ref}` with coercions
	- `uncertainty`: `low|medium|high`
	- Optional `notes`
	- `_debug`: prompt hash, parameters, passages used

The per-sample `.llmrag.json` is written alongside the final report.


## Step 5 — Final label and report

Implementation: `_process_sample` in `../src/rexis/operations/llmrag.py`.
- Final label is derived from `llm_out.score` using the same thresholds as the baseline (`SCORE_THRESHOLD_MALICIOUS`, `SCORE_THRESHOLD_SUSPICIOUS`). If the LLM already labeled `benign` and score is lower, we keep `benign`.
- The final report (`H.report.json`) includes:
	- `schema`: `rexis.llmrag.report.v1`
	- `run_name`, `generated_at`, `duration_sec`
	- `sample`: `{sha256, source_path}`
	- `program`: from features
	- `artifacts`: `features_path`, `llmrag_path`, and an explicit retrieval block with `queries`, `notes`, `passages` (metadata only)
	- `llmrag`: the raw LLM classification JSON (now includes `classification` tags)
	- `classification`: `{ "llm": [...] }` convenience block surfacing the tags at the top level
	- `final`: `{score, label}`
	- `audit`: chronological events if enabled

Run-level report and batch summary:
- `llmrag_summary.json` (directory mode): counts and report paths
- `llmrag-analysis-<RUN_ID>.report.json`: inputs (retrieval/LLM knobs), outputs, environment (e.g., `rexis_version`)


## Audit events

When `--audit` is enabled, `_process_sample` records:
- `pipeline_start`
- `decompile_start` / `decompile_ready`
- `rag_start` / `rag_done`
- `llm_start` / `llm_done`
- `pipeline_done`


## Prerequisites and configuration

- Ghidra at `/opt/ghidra` for decompilation; see `./InstallGhidra.md`.
- OpenAI configuration in `../config/settings.toml` under `[models.openai]` (API key, base URL, embedding/query models).
- Database settings in `../config/settings.toml` `[db]` (used by the PgVector store). Ensure the table/index is prepared as per ingestion guides.
- The pipeline uses Haystack components for embeddings, retrieval, and chat generation.


## Troubleshooting and behavior notes

- Report format is `json` only.
- You can feed existing `*.features.json` instead of a PE to skip decompilation.
- If retrieval fails (store down, network, or auth), the pipeline continues with no passages; the LLM still runs but may return higher uncertainty.
- Rerank is optional; if it fails, the code falls back to fused results without re-ranking.
- Source filters only apply if your documents were ingested with a `source` metadata field (see ingestion guides under `./`).
- The LLM is required to return strict JSON; parsing is robust with a repair step, but complete failures fall back to a safe classification stub for reliability.


## Quick reference: key files

- Orchestrator: `../src/rexis/operations/llmrag.py`
- Retrieval: `../src/rexis/tools/retrieval/main.py`, `ranking.py`, `searches.py`, `store.py`
- LLM: `../src/rexis/tools/llm/main.py`, `messages.py`, `features.py`, `utils.py`
- Decompiler: `../src/rexis/operations/decompile/main.py`
- Config/Constants: `../config/settings.toml`, `../src/rexis/utils/constants.py`
