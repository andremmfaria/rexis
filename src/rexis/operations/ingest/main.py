import json
import time
import uuid
from pathlib import Path
from typing import Dict, List, Literal, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from rexis.operations.ingest.ingest_html import ingest_html_batch, ingest_html_single
from rexis.operations.ingest.ingest_json import ingest_json_batch, ingest_json_single
from rexis.operations.ingest.ingest_pdf import ingest_pdf_batch, ingest_pdf_single
from rexis.operations.ingest.ingest_text import ingest_text_batch, ingest_text_single
from rexis.operations.ingest.utils import discover_paths
from rexis.utils.utils import LOGGER, get_version


def ingest_file_exec(
    ftype: Literal["pdf", "html", "text", "json"],
    target_dir: Optional[Path] = None,
    target_file: Optional[Path] = None,
    batch: int = 5,
    metadata: Dict[str, str] = {},
    out_dir: Path = Path.cwd(),
    run_name: Optional[str] = None,
) -> Path:
    """
    Interface-only router for file ingestion.
    Supports:
      - Single-file mode via --file
      - Batch mode via --dir (recursive discovery)

    ftype: 'pdf' | 'html' | 'text' | 'json'
    """
    start_ts = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))

    # Derive run context aligned with analysis workflows
    run_id: str = run_name or uuid.uuid4().hex
    base_path = f"ingest-analysis-{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = out_dir / base_path
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / f"{base_path}.report.json"

    status: str = "success"
    error_message: Optional[str] = None
    mode: str = "unknown"
    files_discovered: int = 0
    files_processed: int = 0

    try:
        # Validate inputs
        if target_dir and target_file:
            msg = "Both --dir and --file provided; pick one."
            LOGGER.error(msg)
            status = "error"
            error_message = msg
            return report_path
        if not target_dir and not target_file:
            msg = "Neither --dir nor --file provided; one is required."
            LOGGER.error(msg)
            status = "error"
            error_message = msg
            return report_path

        if target_file:
            mode = "single"
            files_discovered = 1
            LOGGER.info("[single] %s -> %s", ftype, target_file)
            if ftype == "pdf":
                ingest_pdf_single(target_file, metadata)
            elif ftype == "html":
                ingest_html_single(target_file, metadata)
            elif ftype == "text":
                ingest_text_single(target_file, metadata)
            elif ftype == "json":
                ingest_json_single(target_file, metadata)
            else:
                LOGGER.error("Unknown file type: %s", ftype)
            files_processed = 1

        elif target_dir:
            mode = "batch"
            paths: List[Path] = discover_paths(ftype, target_dir)
            files_discovered = len(paths)
            if not paths:
                LOGGER.warning("No %s files found under %s", ftype, target_dir)
                files_processed = 0
                return report_path

            LOGGER.info("[batch] %s -> %d file(s), batch=%d", ftype, len(paths), batch)

            if ftype == "pdf":
                ingest_pdf_batch(paths, batch, metadata)
            elif ftype == "html":
                ingest_html_batch(paths, batch, metadata)
            elif ftype == "text":
                ingest_text_batch(paths, batch, metadata)
            elif ftype == "json":
                ingest_json_batch(paths, batch, metadata)
            else:
                LOGGER.error("Unknown file type: %s", ftype)
            files_processed = len(paths)

        else:
            LOGGER.error("Unknown ingestion mode")
            status = "error"
            error_message = "Unknown ingestion mode"
            return report_path
    except Exception as e:
        status = "error"
        error_message = str(e)
        LOGGER.error("Ingestion failed: %s", e)
    finally:
        end_ts = time.time()
        ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts))
        duration_sec = round(end_ts - start_ts, 3)
        summary: Dict[str, int | str | None] = {
            "mode": mode,
            "files_discovered": files_discovered,
            "files_processed": files_processed,
            "batch": batch,
        }
        report: Dict[str, object] = {
            "run_id": run_id,
            "base_path": base_path,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_sec,
            "status": status,
            "error": error_message,
            "summary": summary,
            "inputs": {
                "ftype": ftype,
                "target_dir": str(target_dir) if target_dir else None,
                "target_file": str(target_file) if target_file else None,
                "metadata": metadata,
            },
            "outputs": {
                "run_dir": str(run_dir),
            },
            "environment": {
                "rexis_version": get_version(),
            },
        }
        try:
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            LOGGER.info("Run report written to %s", report_path)
            print(f"[ingest] Run report: {report_path}")
        except Exception as rexc:
            LOGGER.error("Failed to write run report %s: %s", report_path, rexc)
    return report_path
