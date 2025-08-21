import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from haystack import Document
from rexis.operations.ingest.utils import discover_paths
from rexis.tools.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_json_exec(
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
        LOGGER.info("[single] json -> %s", target_file)
        ingest_json_single(target_file, metadata)
        return

    elif target_dir:
        paths: List[Path] = discover_paths("json", target_dir)
        if not paths:
            LOGGER.warning("No json files found under %s", target_dir)
            return

        LOGGER.info("[batch] json -> %d file(s), batch=%d", len(paths), batch)
        ingest_json_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def ingest_json_single(path: Path, metadata: dict) -> None:
    print("Ingesting JSON file:", path)
    doc_list = process_json_file(path, metadata)
    if not doc_list:
        return
    print(f"Indexing {len(doc_list)} JSON record(s) from {path.name}")
    index_documents(documents=doc_list, refresh=True, doc_type="json")
    print("JSON ingestion complete: ", path)


def process_json_file(path: Path, metadata: dict) -> Optional[List[Document]]:
    LOGGER.debug("JSON(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() != ".json":
            print("Skipping non-json file: ", path)
            return None

        try:
            raw_text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read JSON %s: %s", path, e)
            return None

        if not raw_text.strip():
            LOGGER.warning("Empty JSON content: %s", path)
            return None

        try:
            data: Any = json.loads(raw_text)
        except Exception as e:
            LOGGER.error("Failed to parse JSON %s: %s", path, e)
            return None

        if not isinstance(data, list):
            LOGGER.error("Expected a list of records in %s; got %s", path, type(data).__name__)
            return None

        prepared: List[Document] = []
        for rec in data:
            if not isinstance(rec, dict):
                LOGGER.debug("Skipping non-dict record in %s", path)
                continue

            # Prefer top-level sha256_hash, fallback to data.sha256_hash, else hash record JSON
            sha256 = rec.get("sha256_hash") or (rec.get("data") or {}).get("sha256_hash")
            if not sha256:
                try:
                    sha256 = hashlib.sha256(
                        json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
                    ).hexdigest()
                except Exception:
                    LOGGER.error("Failed to compute fallback hash; skipping record")
                    continue

            meta = {
                **(metadata or {}),
                "sha256": sha256,
                "filename": path.name,
                "source": (metadata or {}).get("source", "external"),
                "type": "json",
            }
            if "query_type" in rec:
                meta["query_type"] = rec["query_type"]

            doc = Document(
                id=f"file_json::{sha256}",
                content=json.dumps(rec, ensure_ascii=False),
                meta=meta,
            )
            prepared.append(doc)

        if not prepared:
            LOGGER.warning("No valid records to index from %s", path)
            return None

        return prepared
    except Exception as e:
        LOGGER.error("Failed to ingest JSON %s: %s", path, e, exc_info=True)
        return None


def ingest_json_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No json files to ingest.")
        return

    filtered = [p for p in paths if p.suffix.lower() == ".json"]
    if not filtered:
        LOGGER.warning("No json files to ingest after filtering by extension.")
        return

    # Treat 'batch' as number of batches; split evenly and distribute remainder
    num_batches = max(1, min(batch, len(filtered)))
    base, rem = divmod(len(filtered), num_batches)
    print(
        f"Preparing {len(filtered)} json file(s) for indexing (num_batches={num_batches}, ~{base} per batch, +1 on first {rem})..."
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

    processed = 0
    # Run one thread per chunk concurrently
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        future_map = {
            executor.submit(process_json_batch, chunk, 50, metadata): len(chunk) for chunk in chunks
        }
        for i, fut in enumerate(as_completed(future_map), 1):
            try:
                fut.result()
            except Exception as e:
                LOGGER.error("JSON(batch) failed during chunk: %s", e)
            processed += future_map[fut]
            print(f"Processed JSON batch {i}/{len(chunks)} (progress {processed}/{len(filtered)})")

    print("JSON batch ingestion complete.")


def process_json_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} json file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            docs = process_json_file(path, metadata)
            if docs:
                prepared.extend(docs)

            if len(prepared) >= batch:
                print(f"Indexing JSON batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="json")
                prepared.clear()

        except Exception as e:
            LOGGER.error("Failed to process json documents: %s", e)
            return

    if prepared:
        print(f"Indexing final JSON batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="json")
