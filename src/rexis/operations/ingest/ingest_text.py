import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

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


def ingest_text_exec(
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
        LOGGER.info("[single] text -> %s", target_file)
        ingest_text_single(target_file, metadata)

    elif target_dir:
        paths: List[Path] = discover_paths("text", target_dir)
        if not paths:
            LOGGER.warning("No text files found under %s", target_dir)
            return

        LOGGER.info("[batch] text -> %d file(s), batch=%d", len(paths), batch)
        ingest_text_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def ingest_text_single(path: Path, metadata: dict) -> None:
    print("Ingesting TEXT file:", path)
    if path.suffix.lower() != ".txt":
        print("Skipping non-text file: ", path)
        return

    doc = process_text_file(path, metadata)
    if doc:
        print(f"Indexing 1 TEXT document: {path.name}")
        index_documents(documents=[doc], refresh=True, doc_type="prose")

    print("TEXT ingestion complete: ", path)


def process_text_file(path: Path, metadata: dict) -> Optional[Document]:
    LOGGER.debug("TEXT(single) path: %s (metadata=%s)", path, metadata)
    try:
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read text %s: %s", path, e)
            return None

        if not raw.strip():
            LOGGER.warning("Empty text content: %s", path)
            return None

        text: str = normalize_whitespace(raw)

        payload = {
            "title": path.stem,
            "extracted_text": text,
            "metadata": metadata or {},
        }

        hash_val: str = stable_doc_id_from_path(path)

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
        return doc
    except Exception as e:
        LOGGER.error("Failed to ingest TEXT %s: %s", path, e, exc_info=True)
        return None


def ingest_text_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No text files to ingest.")
        return

    filtered = [p for p in paths if p.suffix.lower() == ".txt"]
    if not filtered:
        LOGGER.warning("No text files to ingest after filtering by extension.")
        return

    # 'batch' is number of batches; split evenly and spread remainder
    num_batches = max(1, min(batch, len(filtered)))
    base, rem = divmod(len(filtered), num_batches)
    print(
        f"Preparing {len(filtered)} text file(s) for indexing (num_batches={num_batches}, ~{base} per batch, +1 on first {rem})..."
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
    progress = Progress(total=len(filtered), prefix="TEXT")
    print_progress(0, progress.total, progress.start_ts, progress.prefix)

    # Run one thread per chunk concurrently
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        futures = [
            executor.submit(process_text_batch, chunk, 3, metadata, progress) for chunk in chunks
        ]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                LOGGER.error("TEXT(batch) failed during chunk: %s", e)

    print("TEXT batch ingestion complete.")


def process_text_batch(paths: List[Path], batch: int, metadata: dict, progress: Progress) -> None:
    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} text file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            doc = process_text_file(path, metadata)
            if doc:
                prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing TEXT batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared.clear()

        except Exception as e:
            LOGGER.error(
                "Failed to process text documents %s: %s",
                [getattr(d, "id", "?") for d in prepared],
                e,
            )
            return
        finally:
            progress.tick(1)

    if prepared:
        print(f"Indexing final TEXT batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="prose")
