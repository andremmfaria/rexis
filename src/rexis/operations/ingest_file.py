import hashlib
import json
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set

import pymupdf
from haystack import Document
from rexis.facade.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_file_exec(
    ftype: Literal["pdf", "html", "text"],
    target_dir: Optional[Path] = None,
    target_file: Optional[Path] = None,
    batch: int = 50,
    metadata: Dict[str, str] = {},
) -> None:
    """
    Interface-only router for file ingestion.
    Supports:
      - Single-file mode via --file
      - Batch mode via --dir (recursive discovery)

    ftype: 'pdf' | 'html' | 'text'
    """
    if target_dir and target_file:
        LOGGER.error("Both --dir and --file provided; pick one.")
        return
    if not target_dir and not target_file:
        LOGGER.error("Neither --dir nor --file provided; one is required.")
        return

    if target_file:
        LOGGER.info("[single] %s -> %s | metadata=%s", ftype, target_file, metadata)
        if ftype == "pdf":
            _ingest_pdf_single(target_file, metadata)
        elif ftype == "html":
            _ingest_html_single(target_file, metadata)
        elif ftype == "text":
            _ingest_text_single(target_file, metadata)
        else:
            LOGGER.error("Unknown file type: %s", ftype)
        return

    elif target_dir:
        paths: List[Path] = _discover_paths(ftype, target_dir)
        if not paths:
            LOGGER.warning("No %s files found under %s", ftype, target_dir)
            return

        LOGGER.info(
            "[batch] %s -> %d file(s), batch=%d | metadata=%s", ftype, len(paths), batch, metadata
        )

        if ftype == "pdf":
            _ingest_pdf_batch(paths, batch, metadata)
        elif ftype == "html":
            _ingest_html_batch(paths, batch, metadata)
        elif ftype == "text":
            _ingest_text_batch(paths, batch, metadata)
        else:
            LOGGER.error("Unknown file type: %s", ftype)

    else:
        LOGGER.error("Unknown ingestion mode")


def _discover_paths(ftype: str, root: Path) -> List[Path]:
    exts: Set = {
        "pdf": {".pdf"},
        "html": {".html", ".htm"},
        "text": {".txt"},
    }[ftype]

    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            results.append(p)
    results.sort()
    LOGGER.info("Discovered %d %s file(s) under %s", len(results), ftype, root)
    return results


def _ingest_pdf_single(path: Path, metadata: dict) -> None:
    try:
        if path.suffix.lower() != ".pdf":
            LOGGER.warning("Skipping non-PDF file: %s", path)
            return

        text = _pdf_to_text(path)
        if not text.strip():
            LOGGER.warning("Empty text extracted from %s", path)
            return

        # Build payload (what goes into .content)
        payload = {
            "local_path": str(path.resolve()),
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

        LOGGER.info("Indexing 1 PDF document: %s", path.name)
        index_documents([doc], refresh=True)

    except Exception as e:
        LOGGER.error("Failed to ingest PDF %s: %s", path, e, exc_info=True)


def _ingest_pdf_batch(paths: List[Path], batch: int, metadata: Dict) -> None:
    if not paths:
        LOGGER.warning("No PDF files to ingest.")
        return

    prepared: List[Document] = []
    total = len(paths)
    LOGGER.info("Preparing %d PDF(s) for indexing (batch=%d)...", total, batch)

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() != ".pdf":
                LOGGER.debug("Skipping non-PDF: %s", path)
                continue

            text = _pdf_to_text(path)
            if not text.strip():
                LOGGER.warning("Empty text extracted from %s", path)
                continue

            payload = {
                "local_path": str(path.resolve()),
                "title": path.stem,
                "extracted_text": _normalize_whitespace(text),
                "metadata": metadata or {},
            }

            hash_val = (_stable_doc_id_from_path(path),)

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
                LOGGER.info("Indexing batch: %d docs (progress %d/%d)", len(prepared), i, total)
                index_documents(prepared, refresh=True)
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process %s: %s", path, e)

    if prepared:
        LOGGER.info("Indexing final batch: %d docs", len(prepared))
        index_documents(prepared, refresh=True)
    LOGGER.info("PDF batch ingestion complete.")


def _ingest_html_single(path: Path, metadata: dict) -> None:
    """TODO: read HTML, clean boilerplate, extract main text, wrap JSON, index"""
    LOGGER.info("HTML(single) placeholder: %s (metadata=%s)", path, metadata)


def _ingest_html_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    """TODO: iterate files in batches, clean + extract text, wrap JSON, index"""
    LOGGER.info(
        "HTML(batch) placeholder: %d files (batch=%d, metadata=%s)", len(paths), batch, metadata
    )


def _ingest_text_single(path: Path, metadata: dict) -> None:
    """TODO: read plain text, normalize, wrap JSON, index"""
    LOGGER.info("TEXT(single) placeholder: %s (metadata=%s)", path, metadata)


def _ingest_text_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    """TODO: iterate files in batches, read + normalize, wrap JSON, index"""
    LOGGER.info(
        "TEXT(batch) placeholder: %d files (batch=%d, metadata=%s)", len(paths), batch, metadata
    )


def _pdf_to_text(path: Path) -> str:
    """
    Extracts and concatenates text from all pages of a PDF file.

    Args:
        path (Path): The file path to the PDF document.

    Returns:
        str: The extracted text from the PDF, with pages separated by newlines.

    Raises:
        FileNotFoundError: If the specified PDF file does not exist.
        Exception: If there is an error opening or reading the PDF file.
    """
    parts: List[str] = []
    with pymupdf.open(path) as doc:
        for page in doc:
            parts.append(page.get_text("text"))
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
