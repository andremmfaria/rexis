import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

import pymupdf
from haystack import Document
from rexis.facade.haystack import index_documents
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
        paths: List[Path] = _discover_paths(target_dir)
        if not paths:
            LOGGER.warning("No pdf files found under %s", target_dir)
            return

        LOGGER.info("[batch] pdf -> %d file(s), batch=%d", len(paths), batch)

        _ingest_pdf_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def _discover_paths(root: Path) -> List[Path]:
    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".pdf"}:
            results.append(p)
    results.sort()
    print(f"Discovered {len(results)} PDF file(s) under {root}")
    return results


def _ingest_pdf_single(path: Path, metadata: dict) -> None:
    print("Ingesting PDF file:", path)
    LOGGER.debug("PDF(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() != ".pdf":
            LOGGER.warning("Skipping non-PDF file: %s", path)
            return

        text = _pdf_to_text(path)
        if not text.strip():
            LOGGER.warning("Empty text extracted from %s", path)
            return

        payload = {
            "title": path.stem,
            "extracted_text": _normalize_whitespace(text),
            "metadata": metadata or {},
        }

        hash_val = _stable_doc_id_from_path(path)

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

            text = _pdf_to_text(path)
            if not text.strip():
                LOGGER.warning("Empty text extracted from %s", path)
                continue

            print("Ingesting PDF file:", path)
            LOGGER.debug("PDF(batch) path: %s (metadata=%s)", path, metadata)

            payload = {
                "title": path.stem,
                "extracted_text": _normalize_whitespace(text),
                "metadata": metadata or {},
            }

            hash_val = _stable_doc_id_from_path(path)

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
                print(f"Indexing batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process %s: %s", path, e)

    if prepared:
        print(f"Indexing final batch: {len(prepared)} docs")
        index_documents(prepared, refresh=True, doc_type="prose")

    print("PDF batch ingestion complete.")


def _pdf_to_text(path: Path) -> str:
    parts: List[str] = []
    try:
        with pymupdf.open(path) as doc:
            for page in doc:
                try:
                    parts.append(page.get_text("text"))
                except Exception as e:
                    LOGGER.warning(f"MuPDF warning on page extraction ({path}): {e}")
    except Exception as e:
        LOGGER.error(f"Failed to open PDF {path}: {e}")
        return ""
    return "\n".join(parts)


def _stable_doc_id_from_path(path: Path) -> str:
    """
    Generates a stable document identifier (SHA-256 hash) from the contents of a file.

    Args:
        path (Path): The path to the file whose contents will be hashed.

    Returns:
        str: The hexadecimal SHA-256 hash of the file's contents.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        PermissionError: If the file cannot be read due to permission issues.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    digest = h.hexdigest()
    return digest


def _normalize_whitespace(s: str) -> str:
    s = s.replace("\r", "")
    import re

    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()
