import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup
from haystack import Document
from rexis.operations.ingest.utils import (
    Progress,
    discover_paths,
    normalize_whitespace,
    print_progress,
    stable_doc_id_from_path,
)
from rexis.tools.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_html_exec(
    target_dir: Optional[Path] = None,
    target_file: Optional[Path] = None,
    batch: int = 5,
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
        ingest_html_single(target_file, metadata)
        return

    elif target_dir:
        paths: List[Path] = discover_paths("html", target_dir)
        if not paths:
            LOGGER.warning("No HTML files found under %s", target_dir)
            return

        LOGGER.info("[batch] html -> %d file(s), batch=%d", len(paths), batch)
        ingest_html_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def ingest_html_single(path: Path, metadata: dict) -> None:
    print("Ingesting HTML file: ", path)

    if path.suffix.lower() not in {".html", ".htm"}:
        print("Skipping non-HTML file: ", path)
        return

    doc = process_html_file(path, metadata)
    if doc:
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    print("HTML ingestion complete: ", path)


def process_html_file(path: Path, metadata: dict) -> Optional[Document]:
    LOGGER.debug("HTML(single) path: %s (metadata=%s)", path, metadata)
    try:
        try:
            html = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read HTML %s: %s", path, e)
            return None

        if not html.strip():
            LOGGER.warning("Empty HTML content: %s", path)
            return None

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

        text: str = normalize_whitespace(main_text)
        if not text:
            LOGGER.warning("Empty text extracted from %s", path)
            return

        payload: Dict[str, Any] = {
            "title": title,
            "extracted_text": text,
            "metadata": metadata or {},
        }

        hash_val: str = stable_doc_id_from_path(path)

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

        return doc

    except Exception as e:
        LOGGER.error("Failed to ingest HTML %s: %s", path, e, exc_info=True)
        return None


def ingest_html_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No HTML files to ingest.")
        return

    filtered = [p for p in paths if p.suffix.lower() in {".html", ".htm"}]
    if not filtered:
        LOGGER.warning("No HTML files to ingest after filtering by extension.")
        return

    # Treat 'batch' as the number of batches; split evenly and distribute remainder to early batches
    num_batches = max(1, min(batch, len(filtered)))
    base, rem = divmod(len(filtered), num_batches)
    print(
        f"Preparing {len(filtered)} HTML file(s) for indexing (num_batches={num_batches}, ~{base} per batch, +1 on first {rem})..."
    )

    # Building chunks
    chunks: List[List[Path]] = []
    idx = 0
    for i in range(num_batches):
        size = base + (1 if i < rem else 0)
        if size <= 0:
            continue
        chunk = filtered[idx : idx + size]
        idx += size
        if chunk:
            chunks.append(chunk)

    # Progress bar shared across threads
    progress = Progress(total=len(filtered), prefix="HTML")
    print_progress(0, progress.total, progress.start_ts, progress.prefix)

    # Run one thread per chunk concurrently
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        futures = [
            executor.submit(process_html_batch, chunk, 3, metadata, progress) for chunk in chunks
        ]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                LOGGER.error("HTML(batch) failed during chunk: %s", e)

    print("HTML batch ingestion complete.")


def process_html_batch(paths: List[Path], batch: int, metadata: dict, progress: Progress) -> None:
    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} HTML file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            doc = process_html_file(path, metadata)
            if doc:
                prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing HTML batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared.clear()

        except Exception as e:
            LOGGER.error("Failed to process html documents %s: %s", [doc.id for doc in prepared], e)
            return
        finally:
            progress.tick(1)

    if prepared:
        print(f"Indexing final HTML batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="prose")
