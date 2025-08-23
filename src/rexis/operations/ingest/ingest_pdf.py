import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from haystack import Document
from rexis.operations.ingest.utils import (
    Progress,
    discover_paths,
    normalize_whitespace,
    pdf_to_text,
    print_progress,
    stable_doc_id_from_path,
)
from rexis.tools.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_pdf_exec(
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
        LOGGER.info("[single] pdf -> %s", target_file)
        ingest_pdf_single(target_file, metadata)

    elif target_dir:
        paths: List[Path] = discover_paths("pdf", target_dir)
        if not paths:
            LOGGER.warning("No pdf files found under %s", target_dir)
            return

        LOGGER.info("[batch] pdf -> %d file(s), batch=%d", len(paths), batch)
        ingest_pdf_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def ingest_pdf_single(path: Path, metadata: dict) -> None:
    print("Ingesting PDF file:", path)
    if path.suffix.lower() != ".pdf":
        print("Skipping non-PDF file: ", path)
        return

    doc = process_pdf_file(path, metadata)
    if doc:
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    print("PDF ingestion complete: ", path)


def process_pdf_file(path: Path, metadata: dict) -> Optional[Document]:
    LOGGER.debug("PDF(single) path: %s (metadata=%s)", path, metadata)
    try:
        text: str = pdf_to_text(path)
        if not text.strip():
            LOGGER.warning("Empty text extracted from %s", path)
            return None

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

        return doc
    except Exception as e:
        LOGGER.error("Failed to ingest PDF %s: %s", path, e, exc_info=True)
        return None


def ingest_pdf_batch(paths: List[Path], batch: int, metadata: Dict) -> None:
    if not paths:
        LOGGER.warning("No PDF files to ingest.")
        return

    filtered = [p for p in paths if p.suffix.lower() == ".pdf"]
    if not filtered:
        LOGGER.warning("No PDF files to ingest after filtering by extension.")
        return

    # Treat 'batch' as number of batches; split inputs evenly and distribute remainder
    num_batches = max(1, min(batch, len(filtered)))
    base, rem = divmod(len(filtered), num_batches)
    print(
        f"Preparing {len(filtered)} PDF(s) for indexing (num_batches={num_batches}, ~{base} per batch, +1 on first {rem})..."
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
    progress = Progress(total=len(filtered), prefix="PDF")
    print_progress(0, progress.total, progress.start_ts, progress.prefix)

    # Run one thread per chunk concurrently
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        futures = [
            executor.submit(process_pdf_batch, chunk, 3, metadata, progress) for chunk in chunks
        ]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                LOGGER.error("PDF(batch) failed during chunk: %s", e)

    print("PDF batch ingestion complete.")


def process_pdf_batch(paths: List[Path], batch: int, metadata: dict, progress: Progress) -> None:
    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} PDF file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            doc = process_pdf_file(path, metadata)
            if doc:
                prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing PDF batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared.clear()

        except Exception as e:
            LOGGER.error(
                "Failed to process pdf documents %s: %s",
                [getattr(d, "id", "?") for d in prepared],
                e,
            )
            return
        finally:
            progress.tick(1)

    if prepared:
        print(f"Indexing final PDF batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="prose")
