## Ingestion pipeline: end-to-end workflow (files -> parse/normalize -> chunk -> embed -> index)

This guide explains how textual sources get ingested into the PgVector document store used by retrieval. It covers CLI usage, per-type processing, chunking/embedding/indexing, metadata, configuration, and outputs—with exact references to the code.

Key code entry points:
- CLI commands: `../src/rexis/cli/ingestion_commands.py`
- Orchestrator/router: `../src/rexis/operations/ingest/main.py` (`ingest_file_exec`)
- Type-specific handlers:
	- PDF: `../src/rexis/operations/ingest/ingest_pdf.py`
	- HTML: `../src/rexis/operations/ingest/ingest_html.py`
	- TEXT: `../src/rexis/operations/ingest/ingest_text.py`
	- JSON: `../src/rexis/operations/ingest/ingest_json.py`
- Utilities: `../src/rexis/operations/ingest/utils.py`
- Indexing pipeline (chunk -> embed -> write): `../src/rexis/tools/haystack.py`
- Vector store init (for retrieval side): `../src/rexis/tools/retrieval/store.py`
- Config/Constants: `../config/settings.toml`, `../src/rexis/utils/constants.py`


## What ingestion does

The pipeline converts input files into Haystack Documents, splits content into chunks, embeds those chunks with OpenAI embeddings, and writes them into a PgVector-backed document store to power hybrid retrieval.

Supported file types: pdf, html, text, json.


## How to run

CLI entrypoint group: `rexis ingest` (see `../src/rexis/cli/main.py`). You can use the generic or typed subcommands:

- Generic:
	- `pdm run rexis ingest file --type pdf --dir <input_dir> -m source=malpedia -o ./data/ingest/pdf`
	- `pdm run rexis ingest file --type html --file <file.html> -m source=vendor -o ./data/ingest/html`
- Typed shortcuts:
	- `pdm run rexis ingest pdf --dir <input_dir> -m source=malpedia -o ./data/ingest/pdf`
	- `pdm run rexis ingest html --dir <input_dir> -m source=malpedia -o ./data/ingest/html`
	- `pdm run rexis ingest text --dir <input_dir> -m source=community -o ./data/ingest/text`
	- `pdm run rexis ingest json --dir <input_dir> -m source=malwarebazaar -o ./data/ingest/json`

Options (from `../src/rexis/cli/ingestion_commands.py`):
- Exactly one of `--dir` or `--file` is required (validated).
- `--batch, -b` controls batching behavior in batch mode (see per-type details below).
- `--metadata, -m key=value` can be repeated; merged into document metadata (e.g., `source=malpedia`).
- `--out-dir, -o` sets the run directory where a run report is written.
- `--run-name, -r` optional tag for the run (defaults to UUID).


## Orchestrator: `ingest_file_exec`

File: `../src/rexis/operations/ingest/main.py`.
- Validates mode, creates a run folder `ingest-analysis-<RUN_ID>/` under `--out-dir`.
- Routes to the correct type-specific ingestion in single-file or batch mode.
- Writes a run-level JSON report with counts, parameters, and environment.

Run report path: `ingest-analysis-<RUN_ID>/ingest-analysis-<RUN_ID>.report.json`.


## Per-type processing in detail

All types ultimately produce Haystack `Document` objects with:
- `id`: stable id (prefix by type)
- `content`: a JSON string payload
- `meta`: metadata including `sha256`, `filename`, `source`, and `type`

Indexing call: `index_documents(documents=[...], refresh=True, doc_type=...)` in `../src/rexis/tools/haystack.py`.

### PDF (`ingest_pdf.py`)

- Single-file: `ingest_pdf_single`
- Batch: `ingest_pdf_batch`
- Extraction:
	- Uses `pymupdf` via `pdf_to_text` in `../src/rexis/operations/ingest/utils.py`.
	- Normalizes whitespace (`normalize_whitespace`).
	- Payload written to `content` as JSON: `{title, extracted_text, metadata}`.
	- `id`: `file_pdf::<sha256(file_bytes)>` using `stable_doc_id_from_path`.
- Batch strategy:
	- The `--batch` flag represents the number of batches, not size per batch.
	- Inputs are split into `num_batches`, then each chunk processes and indexes with a per-chunk mini-batch of size 3.
	- Progress printed via a shared `Progress` bar.

### HTML (`ingest_html.py`)

- Parsing:
	- Reads HTML, strips scripts/styles/nav/header/footer.
	- Title from `<title>` or `<h1>`, fallback to filename stem.
	- Main content from `<article>` or `<main>`, fallback to `body` text.
	- Normalizes whitespace.
	- Payload: `{title, extracted_text, metadata}`.
	- `id`: `file_html::<sha256(file_bytes)>`.
- Batch strategy matches PDF: `--batch` is number of batches; internal per-chunk mini-batch size is 3.

### TEXT (`ingest_text.py`)

- Reads plain text (`.txt`), normalizes whitespace.
- Payload: `{title, extracted_text, metadata}`.
- `id`: `file_text::<sha256(file_bytes)>`.
- Batch strategy matches PDF/HTML (mini-batch size 3).

### JSON (`ingest_json.py`)

- Expects a JSON array of records. Each record should be a dict; non-dict records are skipped.
- `sha256` selection:
	- Prefer `rec.sha256_hash` or `rec.data.sha256_hash`.
	- Else compute SHA-256 of the full record JSON (stable, sorted keys).
- Each record becomes one `Document` with:
	- `id`: `file_json::<sha256>`
	- `content`: the record JSON string
	- `meta`: merges metadata + `{sha256, filename, source, type="json"}`; preserves `query_type` if present
- Batch strategy:
	- `--batch` is number of batches; JSON uses larger internal mini-batches of size 50 for DB writes.


## Indexing pipeline: chunking -> embeddings -> write

Implementation: `../src/rexis/tools/haystack.py`.

1) Prepare documents
- Ensures `content` is a string JSON; sets `meta.parent_id = doc.id`.

2) Split into chunks
- For `doc_type="prose"` (PDF/HTML/TEXT): word-based splitting with length 500 and overlap 50, sentence-aware.
- For `doc_type="json"` (JSON): character-based splitting with length 4000 and overlap 400.
- After initial splitting, token-limit enforcement uses the OpenAI embedding model tokenization to keep each chunk ≤ the model’s max (default from config: `embedding_model_limit`, e.g., 8192 tokens).
- Assigns per-chunk metadata: `chunk_index`, `total_chunks`; chunk `id` becomes `<parent_id>::chunk-<idx>`.

3) Optional LLM-driven tagging
- For each chunk, tags are generated with an LLM (`../src/rexis/tools/data_tagger.py`) reading `[tagger]` settings from `../config/settings.toml`.
- Tags are stored in chunk metadata as `tags` (empty list on failure/disabled).

4) Embed chunks
- Uses `OpenAIDocumentEmbedder` with `config.models.openai.embedding_model` and API key.

5) Write to PgVector
- Thread-safe store/writer singletons prevent concurrent index creation.
- Connection string from `DATABASE_CONNECTION_CONNSTRING` (`../src/rexis/utils/constants.py`) which is composed from `[db]` in `../config/settings.toml`.
- HNSW, cosine similarity, 1536 dims.
- Duplicate policy: `OVERWRITE` when `refresh=True` (default), else `SKIP`.


## Document metadata conventions

Each chunk’s `meta` includes:
- `parent_id`: original document id
- `chunk_index`, `total_chunks`
- Inherited fields: `sha256`, `filename`, `source`, `type`
- Optional `tags`: auto-generated via LLM

Top-level `Document.meta` on the parent (before chunking) is set from ingestion:
- `sha256`: file hash or computed per record (JSON)
- `filename`: input filename
- `source`: your provided source (e.g., `malpedia`, `vendor`, `malwarebazaar`)
- `type`: `pdf|html|text|json`

These fields are available for filtering at retrieval time (e.g., `--source malpedia`).


## Concurrency and batching

- Batch mode splits the input set into `num_batches = min(batch, N)` evenly, with remainder spread to early batches.
- Each batch is processed in its own thread, and within the thread, files are prepared and periodically flushed to the DB in mini-batches (3 for prose, 50 for JSON).
- A shared, thread-safe `Progress` prints bar, rate, ETA.
- The writer (`DocumentWriter`) is serialized under a lock to avoid race conditions.


## Outputs and run reports

- Artifacts from indexing are written to the database; the filesystem artifact is the run report.
- Run report fields include: run id, start/end timestamps, duration, status/error, input parameters, batch counts, and environment (`rexis_version`).
- Location: `ingest-analysis-<RUN_ID>/ingest-analysis-<RUN_ID>.report.json` under `--out-dir`.


## Prerequisites and configuration

- OpenAI API configuration under `[models.openai]` in `../config/settings.toml` (API key, models, embedding limit).
- Database `[db]` in `../config/settings.toml` builds `DATABASE_CONNECTION_CONNSTRING` used by both indexing and retrieval stores.
- Optional tagger settings under `[tagger]` (model, api_key, prompts, concurrency, retries). Tagger can be disabled by setting `enabled=false`.


## Troubleshooting and notes

- If you see “No files found”, verify extensions and paths; discovery is per-type (`discover_paths`).
- Empty text after parsing leads to skipped documents; check HTML cleaning and PDF text extraction.
- Large documents are split and token-limited; very large inputs will create many chunks and take longer to embed.
- If DB connection fails, indexing will error; verify connection string and that the pgvector extension and table exist.
- For consistent `source` filtering during retrieval, always pass `--metadata source=...` during ingestion.


## Quick reference: key files

- CLI: `../src/rexis/cli/ingestion_commands.py`
- Orchestrator: `../src/rexis/operations/ingest/main.py`
- PDF: `../src/rexis/operations/ingest/ingest_pdf.py`
- HTML: `../src/rexis/operations/ingest/ingest_html.py`
- TEXT: `../src/rexis/operations/ingest/ingest_text.py`
- JSON: `../src/rexis/operations/ingest/ingest_json.py`
- Utils: `../src/rexis/operations/ingest/utils.py`
- Indexing: `../src/rexis/tools/haystack.py`
- Retrieval store (for context): `../src/rexis/tools/retrieval/store.py`
- Config: `../config/settings.toml`, `../src/rexis/utils/constants.py`
