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

- **Static Analysis Input:** Decompiled source code and structural features from known malware datasets  
  - Supported decompilation tools include:  
    - [IDA Pro](https://hex-rays.com/ida-pro/)  
    - [Ghidra](https://ghidra-sre.org/)  
    - Any tool producing readable code or bytecode representations suitable for static analysis

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

# Create a .env file for your API keys and database config
cp .env.example .env
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Andre Faria**  
MSc in Applied Cybersecurity  
Technological University Dublin — School of Informatics and Cyber Security  
Research Project: *Enhancing Static Malware Analysis with Large Language Models and Retrieval-Augmented Generation*
