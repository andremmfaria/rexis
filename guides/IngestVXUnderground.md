# Ingesting VX‑Underground PDFs with Rexis

This guide shows how to take PDFs you collected from VX‑Underground and ingest them into your Rexis datastore using the CLI. It complements the harvesting flow in `guides/DataSourcingVXUnderground.md`.

- If you haven’t collected the PDFs yet, start with: `guides/DataSourcingVXUnderground.md`.
- If you already have the PDFs on disk, follow the steps below to index them.

---

## What you need

- A folder containing the downloaded VX‑Underground PDFs (see the sourcing guide).
- Rexis CLI available in your environment.
- PyMuPDF dependency present (used for PDF text extraction). This is handled by the project’s dependencies; if you see an import error for `pymupdf`, install project deps per your setup.

---

## Quick start

- Ingest an entire folder of PDFs (batch mode):

  Optional (copyable) command:
  ```bash
  # Folder ingest (recommended)
  rexis ingest file -t pdf -d /path/to/pdfs -b 50 -m source=vxu year=2012
  ```

- Ingest a single PDF:

  Optional (copyable) command:
  ```bash
  # Single-file ingest
  rexis ingest file -t pdf -f /path/to/pdfs/some_report.pdf -m source=vxu year=2012
  ```

Notes:
- Use `-m key=value` repeatedly to attach metadata (e.g., `source=vxu`, `year=2012`, `topic=APT`).
- Duplicates are naturally deduplicated by file content SHA‑256.

---

## CLI entrypoint and options

Rexis exposes a file ingester via the CLI function `ingest_file` defined in `src/rexis/cli/ingestion_commands.py`.

Key options this command enforces:
- `--type, -t` (required): one of `pdf`, `html`, or `text`.
- Exactly one of:
  - `--dir, -d` (batch mode, recursive) or
  - `--file, -f` (single file).
- `--batch, -b` (default `50`): batch size for indexing when using `--dir`.
- `--metadata, -m key=value`: attach arbitrary metadata; can be supplied multiple times. Duplicate keys are rejected, and values must be in `key=value` form.

The CLI performs strict validation and raises user‑friendly errors for invalid combinations (e.g., both `--dir` and `--file` provided, or malformed metadata).

---

## What happens under the hood

The CLI delegates to `ingest_file_exec` in `src/rexis/operations/ingest_file.py`. Here’s the behavior for PDFs:

- Discovery (when `--dir`):
  - Recursively finds all `*.pdf` files, sorts them, and logs the count.
- Extraction:
  - Opens each PDF with PyMuPDF and extracts page text via `page.get_text("text")`.
  - Normalizes whitespace (collapses multiple spaces, limits blank lines).
  - Skips files that produce empty text.
- Envelope + ID:
  - Wraps content as JSON: `{ title, extracted_text, metadata }`.
  - Computes a stable document ID as `file_pdf::<sha256(file bytes)>`.
  - Sets document metadata including `sha256`, `filename`, `type=pdf`, and any CLI‑provided metadata (e.g., `source=vxu`, `year=2012`). If `source` isn’t supplied, it defaults to `external`.
- Indexing:
  - Batches documents (size controlled by `--batch`, default 50) and sends them to `index_documents(..., doc_type="prose")`.
  - Final partial batch is indexed at the end.

For single‑file mode, the same steps are applied to just one file.

Current non‑PDF handlers (`html`, `text`) are placeholders and log that they’re not implemented yet.

---

## Recommended metadata

Attach metadata to make your corpus easy to query and filter later:
- `source=vxu` — identify VX‑Underground as the provenance.
- `year=<YYYY>` — the APT year folder the report came from.
- Additional tags like `actor=FIN7`, `topic=APT`, `lang=en` as needed.

Example (optional):
```bash
rexis ingest file -t pdf -d ./data/vxunderground/2022 -b 25 -m source=vxu year=2022 topic=APT
```

---

## Duplicate handling

Rexis computes a SHA‑256 of the file contents and uses it in the document ID. If you ingest the same PDF from multiple folders or runs, the ID remains the same and the index de‑duplicates cleanly.

---

## Skips and warnings you may see

- “Skipping non‑PDF” — A different file extension was encountered in the directory.
- “Empty text extracted” — The PDF yielded no extractable text (e.g., images only or protected). Consider OCRing before ingest if needed.
- PyMuPDF open/extraction warnings — Logged per page; ingestion continues for other pages/files.

---

## End‑to‑end example

1) Collect signed Backblaze B2 URLs and download PDFs using the scripts and steps in `guides/DataSourcingVXUnderground.md`.
2) Ingest the downloaded folder with metadata:

   Optional (copyable) command:
   ```bash
   rexis ingest file -t pdf -d /path/to/downloads -b 50 -m source=vxu year=2013
   ```

3) Verify in your Haystack backend that documents are present with the expected metadata and IDs.

---

## Troubleshooting

- `ImportError: No module named 'pymupdf'` — ensure project dependencies are installed per your environment manager. PyMuPDF is required for PDF extraction.
- Nothing gets indexed — check logs for “Empty text extracted” or exceptions from PyMuPDF, and confirm your Haystack backend is configured (see your `config/settings.toml`).
- CLI validation errors — ensure you specify exactly one of `--dir` or `--file`, and that each `-m` flag is in `key=value` form with unique keys.

---

## Related

- Collector: `guides/DataSourcingVXUnderground.md`
- CLI: `src/rexis/cli/ingestion_commands.py` (`ingest_file`)
- Executor: `src/rexis/operations/ingest_file.py` (`ingest_file_exec`)
