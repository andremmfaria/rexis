import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from haystack import Document
from rexis.facade.haystack import index_documents
from rexis.utils.utils import LOGGER


def ingest_json_exec(
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
        LOGGER.info("[single] json -> %s", target_file)
        _ingest_json_single(target_file, metadata)
        return

    elif target_dir:
        paths: List[Path] = _discover_paths(target_dir)
        if not paths:
            LOGGER.warning("No json files found under %s", target_dir)
            return

        LOGGER.info("[batch] json -> %d file(s), batch=%d", len(paths), batch)

        _ingest_json_batch(paths, batch, metadata)

    else:
        LOGGER.error("Unknown ingestion mode")


def _discover_paths(root: Path) -> List[Path]:
    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".json"}:
            results.append(p)
    results.sort()
    print(f"Discovered {len(results)} JSON file(s) under {root}")
    return results


def _ingest_json_single(path: Path, metadata: dict) -> None:
    print("Ingesting JSON file:", path)
    LOGGER.debug("JSON(single) path: %s (metadata=%s)", path, metadata)
    try:
        if path.suffix.lower() != ".json":
            LOGGER.warning("Skipping non-json file: %s", path)
            return

        try:
            raw_text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            LOGGER.error("Failed to read JSON %s: %s", path, e)
            return

        if not raw_text.strip():
            LOGGER.warning("Empty JSON content: %s", path)
            return

        try:
            data: Any = json.loads(raw_text)
        except Exception as e:
            LOGGER.error("Failed to parse JSON %s: %s", path, e)
            return

        if not isinstance(data, list):
            LOGGER.error("Expected a list of records in %s; got %s", path, type(data).__name__)
            return

        prepared: List[Document] = []
        for rec in data:
            if not isinstance(rec, dict):
                LOGGER.debug("Skipping non-dict record in %s", path)
                continue

            # Prefer top-level sha256_hash, fallback to data.sha256_hash, else hash record JSON
            sha256 = (rec.get("sha256_hash") or (rec.get("data") or {}).get("sha256_hash"))
            if not sha256:
                try:
                    import hashlib as _hl
                    sha256 = _hl.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
                except Exception:
                    LOGGER.debug("Failed to compute fallback hash; skipping record")
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
            return

        print(f"Indexing {len(prepared)} JSON record(s) from {path.name}")
        index_documents(documents=prepared, refresh=True, doc_type="json")

    except Exception as e:
        LOGGER.error("Failed to ingest JSON %s: %s", path, e, exc_info=True)

    print("JSON ingestion complete")


def _ingest_json_batch(paths: List[Path], batch: int, metadata: dict) -> None:
    if not paths:
        LOGGER.warning("No json files to ingest.")
        return

    prepared: List[Document] = []
    total = len(paths)
    print(f"Preparing {total} json file(s) for indexing (batch={batch})...")

    for i, path in enumerate(paths, 1):
        try:
            if path.suffix.lower() != ".json":
                LOGGER.debug("Skipping non-json: %s", path)
                continue

            print("Ingesting JSON file:", path)
            LOGGER.debug("JSON(batch) path: %s (metadata=%s)", path, metadata)

            try:
                raw_text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                LOGGER.warning("Failed to read json %s: %s", path, e)
                continue

            if not raw_text.strip():
                LOGGER.warning("Empty json content: %s", path)
                continue

            try:
                data: Any = json.loads(raw_text)
            except Exception as e:
                LOGGER.warning("Failed to parse json %s: %s", path, e)
                continue

            if not isinstance(data, list):
                LOGGER.warning("Skipping %s: expected list of records, got %s", path, type(data).__name__)
                continue

            for rec in data:
                if not isinstance(rec, dict):
                    continue

                sha256 = (rec.get("sha256_hash") or (rec.get("data") or {}).get("sha256_hash"))
                if not sha256:
                    try:
                        import hashlib as _hl
                        sha256 = _hl.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
                    except Exception:
                        continue

                meta = {
                    **(metadata or {}),
                    "sha256": sha256,
                    "filename": path.name,
                    "source": (metadata or {}).get("source", "external"),
                    "type": "json",
                }
                if "query_type" in rec:
                    meta["query_type_src"] = rec["query_type"]

                doc = Document(
                    id=f"file_json::{sha256}",
                    content=json.dumps(rec, ensure_ascii=False),
                    meta=meta,
                )
                prepared.append(doc)

            if len(prepared) >= batch:
                print(f"Indexing JSON batch: {len(prepared)} docs (progress {i}/{total})")
                index_documents(documents=prepared, refresh=True, doc_type="json")
                prepared = []

        except Exception as e:
            LOGGER.warning("Failed to process json %s: %s", path, e)

    if prepared:
        print(f"Indexing final JSON batch: {len(prepared)} docs")
        index_documents(documents=prepared, refresh=True, doc_type="json")

    print("JSON batch ingestion complete.")
