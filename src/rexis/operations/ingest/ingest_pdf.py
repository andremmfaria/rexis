import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from haystack import Document
from rexis.operations.ingest.utils import (
    discover_paths,
    normalize_whitespace,
    pdf_to_text,
    stable_doc_id_from_path,
)
from rexis.tools.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_pdf_exec(
    target_dir: Optional[Path] = None,
    target_file: Optional[Path] = None,
    batch: int = 10,
    metadata: Dict[str, str] = {},
) -> None:
    """
    Interface-only router for file ingestion.
    Supports:
      - Single-file mode via --file
      - Batch mode via --dir (recursive discovery)
    """
    if target_dir and target_file:
        LOGGER.error("Both --dir and --file provided; pick one.")
        return
    if not target_dir and not target_file:
        LOGGER.error("Neither --dir nor --file provided; one is required.")
        return

    if target_file:
        LOGGER.info("[single] pdf -> %s", target_file)
        _ingest_pdf_single(target_file, metadata)

    elif target_dir:
        paths: List[Path] = discover_paths("pdf", target_dir)
        if not paths:
            LOGGER.warning("No pdf files found under %s", target_dir)
            return

        LOGGER.info("[batch] pdf -> %d file(s), batch=%d", len(paths), batch)

        _ingest_pdf_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def _ingest_pdf_single(path: Path, metadata: dict) -> None:
    print("Ingesting PDF file:", path)
    LOGGER.debug("PDF(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() != ".pdf":
            LOGGER.warning("Skipping non-PDF file: %s", path)
            return

        text: str = pdf_to_text(path)
        if not text.strip():
            LOGGER.warning("Empty text extracted from %s", path)
            return

        payload: Dict[str, Any] = {
            "title": path.stem,
            "extracted_text": normalize_whitespace(text),
            "metadata": metadata or {},
        }

        hash_val: str = stable_doc_id_from_path(path)

        # Build Document
        doc = Document(
            id=f"file_pdf::{hash_val}",
            content=json.dumps(payload),
            meta={
                **(metadata or {}),
                "sha256": hash_val,
                "filename": path.name,
                "source": (metadata or {}).get("source", "external"),
                "type": "pdf",
            },
        )

        print(f"Indexing 1 PDF document: {path.name}")
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    except Exception as e:
        LOGGER.error("Failed to ingest PDF %s: %s", path, e, exc_info=True)
        return

    print("PDF ingestion complete.")


def _ingest_pdf_batch(paths: List[Path], batch: int, metadata: Dict) -> None:
    if not paths:
        LOGGER.warning("No PDF files to ingest.")
        return

    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} PDF(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() != ".pdf":
                LOGGER.debug("Skipping non-PDF: %s", path)
                continue

            text: str = pdf_to_text(path)
            if not text.strip():
                LOGGER.warning("Empty text extracted from %s", path)
                continue

            print("Ingesting PDF file:", path)
            LOGGER.debug("PDF(batch) path: %s (metadata=%s)", path, metadata)

            payload: Dict[str, Any] = {
                "title": path.stem,
                "extracted_text": normalize_whitespace(text),
                "metadata": metadata or {},
            }

            hash_val: str = stable_doc_id_from_path(path)

            doc = Document(
                id=f"file_pdf::{hash_val}",
                content=json.dumps(payload),
                meta={
                    **(metadata or {}),
                    "sha256": hash_val,
                    "filename": path.name,
                    "source": (metadata or {}).get("source", "external"),
                    "type": "pdf",
                },
            )
            prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing PDF batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared.clear()

        except Exception as e:
            LOGGER.error("Failed to process pdf documents %s: %s", [doc.id for doc in prepared], e)
            return

    if prepared:
        print(f"Indexing final PDF batch: {len(prepared)} docs")
        index_documents(prepared, refresh=True, doc_type="prose")

    print("PDF batch ingestion complete.")
