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
  - [OpenAI](https://platform.openai.com/) — for general-purpose, high-accuracy LLM queries  
  - [DeepSeek](https://github.com/deepseek-ai) — for code-centric language understanding and reasoning

- **Static Analysis Input:**  
  - Decompiled source code and structural features from known malware datasets  
  - Recommended decompilation tools include:  
    - [IDA Pro](https://hex-rays.com/ida-pro/)  
    - [Ghidra](https://ghidra-sre.org/)  
    - Any tool producing readable code or bytecode representations suitable for static analysis

- **Datastore (Vector Database):**  
  - [PostgreSQL](https://www.postgresql.org/) with [pgvector](https://github.com/pgvector/pgvector) extension  
  - Used to store and query embeddings for Retrieval-Augmented Generation (RAG)  
  - Integrated with the Haystack pipeline for vector-based semantic search and context retrieval


---

## 📂 Project Structure _(Coming Soon)_

> This section will outline the repo structure, including modules for data ingestion, RAG querying, LLM prompts, and evaluation.

---

## 📈 Evaluation & Benchmarks _(Planned)_

> REXIS will be tested against traditional static analysis tools and scored based on:
- Accuracy of classification
- Justifiability of output
- Contextual relevance of LLM explanations
- Efficiency of the analysis pipeline

---

## ⚙️ Installation & Setup

REXIS uses Python `3.13+` and is managed using [PDM](https://pdm.fming.dev/).  
Ensure you have Python 3.13 installed and [PostgreSQL](https://www.postgresql.org/) running with the [pgvector](https://github.com/pgvector/pgvector) extension enabled.

### 📦 Prerequisites

- Python 3.13+
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

---

## 🧪 Usage

REXIS is containerized for reproducibility and ease of development. The project uses `docker-compose` to manage two main services:

- `app`: The main application (e.g. RAG pipeline, interface, analysis logic)
- `db`: PostgreSQL with the `pgvector` extension for vector-based semantic search

---

### 🐳 Step-by-Step Instructions

1. **Create your `.env` file** in the root of the project by copying from the template file (`.env-template`):

```dotenv
POSTGRES_USER=postgres
POSTGRES_PASSWORD=super_secret_password
POSTGRES_DB=rexis
```

2. **Build and start the containers**:

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

- `collect` — fetch raw data from sources
- `ingest` — index files into the vector store
- `query` — run analysis queries over the indexed data

---

## � collect

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
rexis ingest file --type [pdf|html|text|json] (--dir DIR | --file FILE) [--batch N] [-m key=value ...]
```

### convenience shortcuts

```bash
rexis ingest pdf  (--dir DIR | --file FILE) [--batch N] [-m key=value ...]
rexis ingest html (--dir DIR | --file FILE) [--batch N] [-m key=value ...]
rexis ingest text (--dir DIR | --file FILE) [--batch N] [-m key=value ...]
rexis ingest json (--dir DIR | --file FILE) [--batch N] [-m key=value ...]
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

## 🔎 query

Run analysis over the indexed corpus.

Two subcommands are exposed; depending on your branch/state, they may be WIP:

```bash
rexis query baseline --sha256 SHA256
rexis query llmrag   --sha256 SHA256 [--top-k N] [--temperature F] [--model NAME]
```

- `baseline` is intended for a static, non-LLM baseline
- `llmrag` retrieves context and queries an LLM (defaults to `gpt-4o`)

Example:

```bash
rexis query llmrag --sha256 abcdef... --top-k 5 --temperature 0.2 --model gpt-4o
```

---

## 🧪 Data Flow (at a glance)

1) `collect` writes JSON manifests and optional scraped artifacts
2) `ingest` normalizes and indexes content into pgvector
3) `query` retrieves semantically relevant docs and asks the LLM

---

## 🧭 Project Structure (high level)

- `src/rexis/cli` — Typer-based CLI (collect, ingest, query)
- `src/rexis/operations/ingest` — file-type-specific ingestion
- `src/rexis/operations/analyse.py` — query pipeline (Haystack + OpenAI)
- `src/rexis/facade` — service facades (e.g., VirusTotal, MalwareBazaar, Haystack)
- `config/` — Dynaconf settings and secrets
- `data/` — sample datasets and collected artifacts (gitignored in real usage)

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Andre Faria**  
MSc in Applied Cybersecurity  
Technological University Dublin — School of Informatics and Cyber Security  
Research Project: *Enhancing Static Malware Analysis with Large Language Models and Retrieval-Augmented Generation*
