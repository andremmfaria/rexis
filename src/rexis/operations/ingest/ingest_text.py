import json
from pathlib import Path
from typing import Dict, List, Optional

from haystack import Document
from rexis.operations.ingest.utils import (
    discover_paths,
    normalize_whitespace,
    stable_doc_id_from_path,
)
from rexis.tools.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_text_exec(
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
        LOGGER.info("[single] text -> %s", target_file)
        _ingest_text_single(target_file, metadata)

    elif target_dir:
        paths: List[Path] = discover_paths("text", target_dir)
        if not paths:
            LOGGER.warning("No text files found under %s", target_dir)
            return

        LOGGER.info("[batch] text -> %d file(s), batch=%d", len(paths), batch)

        _ingest_text_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


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
        print(f"Indexing 1 TEXT document: {path.name}")
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
    print(f"Preparing {total} text file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() != ".txt":
                LOGGER.debug("Skipping non-text: %s", path)
                continue

            print("Ingesting TEXT file:", path)
            LOGGER.debug("TEXT(batch) path: %s (metadata=%s)", path, metadata)

            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                LOGGER.warning("Failed to read text %s: %s", path, e)
                continue

            if not raw.strip():
                LOGGER.warning("Empty text content: %s", path)
                continue

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

            prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing TEXT batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="prose")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process text %s: %s", path, e)

    if prepared:
        print(f"Indexing final TEXT batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="prose")

    print("TEXT batch ingestion complete.")
