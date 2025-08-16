import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from bs4 import BeautifulSoup
from haystack import Document
from rexis.facade.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_html_exec(
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
        LOGGER.info("[single] html -> %s", target_file)
        _ingest_html_single(target_file, metadata)
        return

    elif target_dir:
        paths: List[Path] = _discover_paths(target_dir)
        if not paths:
            LOGGER.warning("No HTML files found under %s", target_dir)
            return

        LOGGER.info("[batch] html -> %d file(s), batch=%d", len(paths), batch)

        _ingest_html_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def _discover_paths(root: Path) -> List[Path]:
    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".html", ".htm"}:
            results.append(p)
    results.sort()
    print(f"Discovered {len(results)} HTML file(s) under {root}")
    return results


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
        print(f"Indexing 1 HTML document: {path.name}")
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
    print(f"Preparing {total} HTML file(s) for indexing (batch={batch})...")

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
                print(f"Indexing HTML batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process HTML %s: %s", path, e)

    if prepared:
        print(f"Indexing final HTML batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="prose")

    print("HTML batch ingestion complete.")


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
