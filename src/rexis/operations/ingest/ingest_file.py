import hashlib
import json
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set

import pymupdf
from bs4 import BeautifulSoup
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
        LOGGER.info("[single] %s -> %s", ftype, target_file)
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

        LOGGER.info("[batch] %s -> %d file(s), batch=%d", ftype, len(paths), batch)

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
    print("Discovered %d %s file(s) under %s", len(results), ftype, root)
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

        print("Indexing 1 PDF document: %s", path.name)
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
    print("Preparing %d PDF(s) for indexing (batch=%d)...", total, batch)

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
                print("Indexing batch: %d docs (progress %d/%d)", len(prepared), i, total)
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process %s: %s", path, e)

    if prepared:
        print("Indexing final batch: %d docs", len(prepared))
        index_documents(prepared, refresh=True, doc_type="prose")

    print("PDF batch ingestion complete.")


def _ingest_html_single(path: Path, metadata: dict) -> None:
    print("Ingesting HTML file:", path)
    LOGGER.debug("HTML(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() not in {".html", ".htm"}:
            LOGGER.warning("Skipping non-HTML file: %s", path)
            return

        try:
            html = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read HTML %s: %s", path, e)
            return

        if not html.strip():
            LOGGER.warning("Empty HTML content: %s", path)
            return

        soup = BeautifulSoup(html, "html.parser")

        # Remove non-content elements
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        for tag in soup.find_all(["header", "footer", "nav", "aside"]):
            tag.decompose()

        # Title selection
        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        if not title:
            h1 = soup.find("h1")
            if h1:
                h1_text = h1.get_text(strip=True)
                if h1_text:
                    title = h1_text
        if not title:
            title = path.stem

        # Main text extraction: prefer <article>, then <main>, else body text
        main_text = ""
        main_node = soup.find("article") or soup.find("main")
        if main_node:
            main_text = main_node.get_text(separator="\n", strip=True)
        else:
            body = soup.body or soup
            main_text = body.get_text(separator="\n", strip=True)

        text = _normalize_whitespace(main_text)
        if not text:
            LOGGER.warning("Empty text extracted from %s", path)
            return

        payload = {
            "title": title,
            "extracted_text": text,
            "metadata": metadata or {},
        }

        hash_val = _stable_doc_id_from_path(path)

        doc = Document(
            id=f"file_html::{hash_val}",
            content=json.dumps(payload),
            meta={
                **(metadata or {}),
                "sha256": hash_val,
                "filename": path.name,
                "source": (metadata or {}).get("source", "external"),
                "type": "html",
            },
        )

        print("Indexing 1 HTML document: %s", path.name)
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    except Exception as e:
        LOGGER.error("Failed to ingest HTML %s: %s", path, e, exc_info=True)

    print("HTML ingestion complete.")


def _ingest_html_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No HTML files to ingest.")
        return

    prepared: List[Document] = []
    total = len(paths)
    print("Preparing %d HTML file(s) for indexing (batch=%d)...", total, batch)

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() not in {".html", ".htm"}:
                LOGGER.debug("Skipping non-HTML: %s", path)
                continue

            print("Ingesting HTML file:", path)
            LOGGER.debug("HTML(batch) path: %s (metadata=%s)", path, metadata)

            try:
                html = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                LOGGER.warning("Failed to read HTML %s: %s", path, e)
                continue

            if not html.strip():
                LOGGER.warning("Empty HTML content: %s", path)
                continue

            soup = BeautifulSoup(html, "html.parser")

            # Remove non-content elements
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            for tag in soup.find_all(["header", "footer", "nav", "aside"]):
                tag.decompose()

            # Title selection
            title = None
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            if not title:
                h1 = soup.find("h1")
                if h1:
                    h1_text = h1.get_text(strip=True)
                    if h1_text:
                        title = h1_text
            if not title:
                title = path.stem

            # Main text extraction
            main_node = soup.find("article") or soup.find("main")
            if main_node:
                main_text = main_node.get_text(separator="\n", strip=True)
            else:
                body = soup.body or soup
                main_text = body.get_text(separator="\n", strip=True)

            text = _normalize_whitespace(main_text)
            if not text:
                LOGGER.warning("Empty text extracted from %s", path)
                continue

            payload = {
                "title": title,
                "extracted_text": text,
                "metadata": metadata or {},
            }

            hash_val = _stable_doc_id_from_path(path)

            doc = Document(
                id=f"file_html::{hash_val}",
                content=json.dumps(payload),
                meta={
                    **(metadata or {}),
                    "sha256": hash_val,
                    "filename": path.name,
                    "source": (metadata or {}).get("source", "external"),
                    "type": "html",
                },
            )

            prepared.append(doc)

            if len(prepared) >= batch:
                print(
                    "Indexing HTML batch: %d docs (progress %d/%d)", len(prepared), i, total
                )
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process HTML %s: %s", path, e)

    if prepared:
        print("Indexing final HTML batch: %d docs", len(prepared))
        index_documents(documents=prepared, refresh=True, doc_type="prose")

    print("HTML batch ingestion complete.")


def _ingest_text_single(path: Path, metadata: dict) -> None:
    print("Ingesting TEXT file:", path)
    LOGGER.debug("TEXT(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() != ".txt":
            LOGGER.warning("Skipping non-text file: %s", path)
            return

        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read text %s: %s", path, e)
            return

        if not raw.strip():
            LOGGER.warning("Empty text content: %s", path)
            return

        text = _normalize_whitespace(raw)

        payload = {
            "title": path.stem,
            "extracted_text": text,
            "metadata": metadata or {},
        }

        hash_val = _stable_doc_id_from_path(path)

        doc = Document(
            id=f"file_text::{hash_val}",
            content=json.dumps(payload),
            meta={
                **(metadata or {}),
                "sha256": hash_val,
                "filename": path.name,
                "source": (metadata or {}).get("source", "external"),
                "type": "text",
            },
        )

        print("Indexing 1 TEXT document: %s", path.name)
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    except Exception as e:
        LOGGER.error("Failed to ingest TEXT %s: %s", path, e, exc_info=True)

    print("TEXT ingestion complete")


def _ingest_text_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No text files to ingest.")
        return

    prepared: List[Document] = []
    total = len(paths)
    print("Preparing %d text file(s) for indexing (batch=%d)...", total, batch)

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() != ".txt":
                LOGGER.debug("Skipping non-text: %s", path)
                continue

            print("Ingesting HTML file:", path)
            LOGGER.debug("TEXT(batch) path: %s (metadata=%s)", path, metadata)

            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                LOGGER.warning("Failed to read text %s: %s", path, e)
                continue

            if not raw.strip():
                LOGGER.warning("Empty text content: %s", path)
                continue

            text = _normalize_whitespace(raw)

            payload = {
                "title": path.stem,
                "extracted_text": text,
                "metadata": metadata or {},
            }

            hash_val = _stable_doc_id_from_path(path)

            doc = Document(
                id=f"file_text::{hash_val}",
                content=json.dumps(payload),
                meta={
                    **(metadata or {}),
                    "sha256": hash_val,
                    "filename": path.name,
                    "source": (metadata or {}).get("source", "external"),
                    "type": "text",
                },
            )

            prepared.append(doc)

            if len(prepared) >= batch:
                print(
                    "Indexing TEXT batch: %d docs (progress %d/%d)", len(prepared), i, total
                )
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process text %s: %s", path, e)

    if prepared:
        print("Indexing final TEXT batch: %d docs", len(prepared))
        index_documents(documents=prepared, refresh=True, doc_type="prose")

    print("TEXT batch ingestion complete.")


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
