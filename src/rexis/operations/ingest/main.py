from pathlib import Path
from typing import Dict, List, Literal, Optional, Set
from rexis.operations.ingest.ingest_html import _ingest_html_batch, _ingest_html_single
from rexis.operations.ingest.ingest_json import _ingest_json_batch, _ingest_json_single
from rexis.operations.ingest.ingest_pdf import _ingest_pdf_batch, _ingest_pdf_single
from rexis.operations.ingest.ingest_text import _ingest_text_batch, _ingest_text_single
from rexis.utils.utils import LOGGER


def ingest_file_exec(
    ftype: Literal["pdf", "html", "text", "json"],
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

    ftype: 'pdf' | 'html' | 'text' | 'json'
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
        elif ftype == "json":
            _ingest_json_single(target_file, metadata)
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
        elif ftype == "json":
            _ingest_json_batch(paths, batch, metadata)
        else:
            LOGGER.error("Unknown file type: %s", ftype)

    else:
        LOGGER.error("Unknown ingestion mode")
        
        
def _discover_paths(ftype: str, root: Path) -> List[Path]:
    exts: Set = {
        "pdf": {".pdf"},
        "html": {".html", ".htm"},
        "text": {".txt"},
        "json": {".json"},
    }[ftype]

    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            results.append(p)
    results.sort()
    print(f"Discovered {len(results)} {ftype} file(s) under {root}")
    return results
