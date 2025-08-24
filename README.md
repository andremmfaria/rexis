# 🔍 REXIS — Retrieval-Enhanced eXploration of Infected Software

**REXIS** is an experimental framework designed to enhance static malware analysis using Large Language Models (LLMs) integrated with Retrieval-Augmented Generation (RAG). This project explores how contextual retrieval from external knowledge sources can improve the accuracy, interpretability, and justifiability of LLM-based malware classification.

Built for cybersecurity research, **REXIS** focuses on analyzing static features (e.g., bytecode, file structure, API calls) and comparing its performance against traditional static analysis techniques.

---

## ✨ Key Features

- 📦 Static malware analysis with LLMs  
- 🔍 Context-aware insights using Retrieval-Augmented Generation  
- 📊 Benchmarking against traditional detection techniques  
- 🧠 Emphasis on explainability and contextual reasoning  

---

## 🛠️ Toolchain

- **Code Retrieval & RAG Pipeline:**  
  - [Haystack](https://github.com/deepset-ai/haystack) — used to build the pipeline between decompiled malware samples and the LLM

- **AI Engine:**  
  - [OpenAI](https://platform.openai.com/) - for general-purpose, high-accuracy LLM queries  
  - [DeepSeek](https://github.com/deepseek-ai) - for code-centric language understanding and reasoning

- **Static Analysis Input:**  
  - [Ghidra](https://ghidra-sre.org/) - Decompiled source code and structural features from known malware datasets

- **Datastore (Vector Database):**  
  - [PostgreSQL](https://www.postgresql.org/) with [pgvector](https://github.com/pgvector/pgvector) extension  
  - Used to store and query embeddings for Retrieval-Augmented Generation (RAG)  
  - Integrated with the Haystack pipeline for vector-based semantic search and context retrieval


---

## 📂 Project Structure

High-level layout you’ll interact with most:

- `src/rexis/cli` — Typer-based CLI entrypoints
  - `collect` (Malpedia, MalwareBazaar)
  - `ingest` (pdf, html, text, json, or generic `file`)
  - `analyse` (baseline, llmrag)
  - `decompile` (Ghidra/pyghidra-based feature extraction)
- `src/rexis/operations` — implementation modules
  - `collect/` — Malpedia and MalwareBazaar collectors
  - `ingest/` — content parsers and indexers
  - `baseline.py` — static heuristic baseline pipeline
  - `llmrag.py` — RAG + LLM analysis pipeline
  - `decompile/` — Ghidra integration
- `config/` — Dynaconf settings and secrets
- `data/` — sample datasets and collected artifacts (local only)
- `.docker/` — Docker build context for Postgres + pgvector

---

## 📈 Evaluation & Benchmarks _(Planned)_

> REXIS will be tested against traditional static analysis tools and scored based on:
- Accuracy of classification
- Justifiability of output
- Contextual relevance of LLM explanations
- Efficiency of the analysis pipeline

---

## ⚙️ Installation & Setup

REXIS targets Python `3.11–3.13` and is managed with [PDM](https://pdm.fming.dev/).  
You’ll also need [PostgreSQL](https://www.postgresql.org/) with the [pgvector](https://github.com/pgvector/pgvector) extension enabled.

### 📦 Prerequisites

- Python 3.11–3.13
- PDM (`pip install pdm`)
- PostgreSQL with pgvector extension
- OpenAI and/or DeepSeek API credentials

### 🚀 Setup Steps

```bash
# Clone the repo
git clone https://github.com/andremmfaria/rexis
cd rexis

# Install dependencies
pdm install

# Create a ./config/.secrets.toml file for your API keys and database config
cp ./config/.secrets_template.toml ./config/.secrets.toml
```

Secrets keys and the database password are read by Dynaconf via `config/settings.toml`. Populate `config/.secrets.toml` with the following keys (values are placeholders):

```
db_password = "super_secret_password-..."
openai_api_key = "sk-..."
deepseek_api_key = "dseek-..."
malware_bazaar_api_key = "malw-bazaar-..."
virus_total_api_key = "vt-..."
```
Note: The provided template file may contain a typo for the MalwareBazaar key. Use `malware_bazaar_api_key` exactly as shown above to match `config/settings.toml`.

Database connection defaults live in `config/settings.toml`:

```toml
[db]
host = "localhost"
port = 5432
name = "rexis"
user = "postgres"
password = "@get db_password"
```

---

## 🧪 Usage

REXIS uses Docker primarily for the database. Run the app locally (via PDM) and connect to Postgres running in Docker.

Services:

- `db`: PostgreSQL with the `pgvector` extension for vector-based semantic search

---

### 🐳 Step-by-Step Instructions

1. **Create your `.env` file** in the root of the project by copying from the example file (`.env.example`):

```dotenv
POSTGRES_USER=postgres
POSTGRES_PASSWORD=super_secret_password
POSTGRES_DB=rexis
```

2. **Build and start the database container**:

```bash
docker compose up --build
```

3. **App source code and configuration**:
  - Application code lives in `./src/`
  - Configuration files (via Dynaconf) are in `./config/`

4. **Stopping the containers**:

```bash
docker compose down
```

5. **Persistent data**:  
PostgreSQL data is stored in a Docker volume named `pgdata` and will persist between restarts.

6. **Verify DB connection from app** (optional):
  - DB connection parameters are read from `config/settings.toml` (`[db]` section) and secrets in `config/.secrets.toml`.

---

## 🧰 CLI Overview

The primary entry point is the `rexis` command.

Global options:

- `-v` / `-vv` increase verbosity
- `-V` / `--version` prints the version and exits

Use `-h` or `--help` on any command/subcommand for details.

### Top-level

```bash
rexis --help
```

Subcommands:

- `collect` — gather raw malware intelligence
  - `malpedia` – retrieve families and actors from Malpedia
  - `malwarebazaar` – fetch samples from MalwareBazaar
- `ingest` — normalise and index files into the vector store
  - `file`, `pdf`, `html`, `text`, `json`
- `analyse` — run analysis pipelines over samples
  - `baseline`, `llmrag`
- `decompile` — decompile a binary and extract features via Ghidra

---

## 🧺 collect

Helpers to gather raw intel before (optionally) ingesting.

### malpedia

```bash
rexis collect malpedia \
  [--family-id ID] [--actor-id ID] [--search-term TEXT] \
  [--start-date YYYY-MM-DD] [--end-date YYYY-MM-DD] \
  [--max N] [--run-name NAME] [--output-dir PATH] [--ingest]
```

Options:

- `--family-id`, `--actor-id`, or `--search-term` to filter
- `--start-date`, `--end-date` to time-bound results
- `--max` limit items after filtering
- `--run-name` custom run identifier; autogenerated if omitted
- `--output-dir` where JSON + scraped docs are written
- `--ingest` immediately indexes discovered documents

Example:

```bash
rexis collect malpedia -s CobaltStrike --start-date 2024-01-01 --end-date 2024-12-31 -o data/malpedia --ingest
```

### malwarebazaar

```bash
rexis collect malwarebazaar \
  [--tags TAGS] [--fetch-limit N] [--batch N] \
  [--hash SHA256 | --hash-file FILE] \
  [--run-name NAME] [--output-dir PATH] [--ingest]
```

Options:

- `--tags` comma-separated tags (requires `--batch` for ingestion sizing)
- `--fetch-limit` per-tag fetch cap
- `--hash` single SHA256, or `--hash-file` list of hashes
- `--run-name`, `--output-dir`, `--ingest` as above

Example:

```bash
rexis collect malwarebazaar -t ransomware,exe --fetch-limit 50 -o data/malwarebazaar --ingest
```

---

## 🧩 ingest

Index files into the vector store. Provide exactly one of `--dir` or `--file`.

### generic file

```bash
rexis ingest file --type [pdf|html|text|json] (--dir DIR | --file FILE) [--batch N] [-m key=value ...] [--out-dir PATH] [--run-name NAME]
```

### convenience shortcuts

```bash
rexis ingest pdf  (--dir DIR | --file FILE) [--batch N] [-m key=value ...] [--out-dir PATH] [--run-name NAME]
rexis ingest html (--dir DIR | --file FILE) [--batch N] [-m key=value ...] [--out-dir PATH] [--run-name NAME]
rexis ingest text (--dir DIR | --file FILE) [--batch N] [-m key=value ...] [--out-dir PATH] [--run-name NAME]
rexis ingest json (--dir DIR | --file FILE) [--batch N] [-m key=value ...] [--out-dir PATH] [--run-name NAME]
```

Notes:

- `--batch` controls chunking for bulk indexing
- `-m/--metadata` accepts repeated key=value pairs (stored with documents)

Examples:

```bash
rexis ingest pdf --dir data/vxunderground/2022 -m source=vxug -m year=2022
rexis ingest json --file data/malwarebazaar/MbExe-20250816T161546Z.json -m source=malwarebazaar
```

---

## 🔎 analyse

Run analysis over samples with either a static baseline or an LLM+RAG pipeline.

Two subcommands are exposed; depending on your branch/state, they may be WIP:

Common options:

```bash
rexis analyse baseline \
  --input PATH [--out-dir PATH] [--run-name NAME] [--overwrite] [--format json] \
  [--project-dir PATH] [--parallel N] [--rules FILE] [--min-severity info|warn|error] \
  [--vt] [--vt-timeout SEC] [--vt-qpm N] [--audit/--no-audit]

rexis analyse llmrag \
  --input PATH [--out-dir PATH] [--run-name NAME] [--overwrite] [--format json] \
  [--project-dir PATH] [--parallel N] \
  [--top-k-dense N] [--top-k-keyword N] [--final-top-k N] [--join rrf|merge] \
  [--rerank-top-k N] [--ranker-model NAME] [--source NAME ...] \
  [--model NAME] [--temperature F] [--max-tokens N] [--seed N] [--json-mode/--no-json-mode] \
  [--audit/--no-audit]
```

Notes:

- Baseline can optionally enrich with VirusTotal (`--vt`).
- LLMRAG defaults: retriever fusion via RRF, generator model `gpt-4o-2024-08-06`.

Examples:

```bash
# Baseline over a single PE sample
pdm run rexis analyse baseline -i ./data/samples/c6e3....exe -o ./data/analysis/baseline

# LLM+RAG over a sample (as used in development)
pdm run rexis analyse llmrag -i ./data/samples/c6e3....exe -o ./data/analysis/llmrag --final-top-k 8
```

---

## 🛠 decompile

Decompile a binary and extract features using Ghidra.

```bash
rexis decompile --file FILE --out-dir DIR [--overwrite] [--project-dir PATH] [--project-name NAME] [--run-name NAME]
```

Example:

```bash
pdm run rexis decompile -f ./data/samples/c6e3....exe -o ./data/decompiled
```

---

## 🧪 Data Flow (at a glance)

1) `collect` writes JSON manifests and optional scraped artifacts
2) `ingest` normalizes and indexes content into pgvector
3) `analyse` retrieves context (for LLMRAG) and produces reports

---

## 🧭 Project Structure (high level)

- `src/rexis/cli` — Typer-based CLI (collect, ingest, analyse, decompile)
- `src/rexis/operations/ingest` — file-type-specific ingestion
- `src/rexis/operations/baseline.py` — static baseline pipeline
- `src/rexis/operations/llmrag.py` — LLMRAG pipeline (Haystack + OpenAI)
- `src/rexis/operations/decompile` — decompiler integration (Ghidra)
- `config/` — Dynaconf settings and secrets
- `data/` — sample datasets and collected artifacts (gitignored in real usage)

---

## 📖 Further Reading

- [BaselinePipeline.md](guides/BaselinePipeline.md)
- [IngestionPipeline.md](guides/IngestionPipeline.md)
- [LLMRagPipeline.md](guides/LLMRagPipeline.md)
- [WritingHeuristicRules.md](guides/WritingHeuristicRules.md)
- [Reconciliation.md](guides/Reconciliation.md)

For questions or contributions, open an issue or pull request on GitHub.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Andre Faria**  
MSc in Applied Cybersecurity  
Technological University Dublin — School of Informatics and Cyber Security  
Research Project: *Enhancing Static Malware Analysis with Large Language Models and Retrieval-Augmented Generation*
