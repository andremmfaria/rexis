import concurrent.futures
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rexis.utils.utils import LOGGER, get_version, iter_pe_files, now_iso, sha256, write_json


def analyze_llmrag_exec(
    input_path: Path,
    out_dir: Path,
    run_name: str,
    overwrite: bool,
    report_format: str,
    project_dir: Path | None,
    parallel: int,
    audit: bool,
) -> Tuple[Path, Path]:
    """
    Orchestrates the llm+rag pipeline for a file or directory.
    Returns (primary_output_path, run_report_path):
      - primary_output_path: single-file -> <sha256>.report.json; directory -> llmrag_summary.json
      - run_report_path:     <run_base>.report.json with inputs/outputs summary (like decompile.py)
    """
    if report_format.lower() != "json":
        raise ValueError("Only 'json' report format is currently supported")

    # Create a per-run directory (aligned with baseline.py style)
    start_ts: float = time.time()
    started_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))
    base_path = f"llmrag-analysis-{run_name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir: Path = out_dir / base_path
    run_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Starting llmrag analysis (run={run_name}) -> {run_dir}")

    # Run-level audit log
    run_audit: List[Dict[str, Any]] = []
    if audit:
        run_audit.append({"ts": now_iso(), "event": "run_start", "input": str(input_path)})

    # Determine targets (basic PE discovery for directory; single file otherwise)
    if input_path.is_dir():
        targets = iter_pe_files(input_path)
        if not targets:
            raise FileNotFoundError(f"No PE files found under: {input_path}")
        print(f"Discovered {len(targets)} PE file(s) under {input_path}")
    else:
        targets = [input_path]

    if audit:
        run_audit.append({"ts": now_iso(), "event": "targets_discovered", "count": len(targets)})

    # Execution lifecycle like baseline.py
    status: str = "success"
    error_message: Optional[str] = None
    primary_output: Optional[Path] = None
    reports: List[Path] = []

    def _worker(target: Path) -> Path:
        print(f"Analyzing file: {target}")
        # Produce stub per-sample reports (placeholders for the real pipeline steps)
        if target.suffix.lower() == ".json" and target.name.endswith(".features.json"):
            # Try to derive sha256 from filename; fallback to loading the file
            stem = target.name[: -len(".features.json")]
            if len(stem) == 64:
                sha = stem.lower()
            else:
                try:
                    with target.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                    sha = (data.get("program") or {}).get("sha256") or stem
                except Exception:
                    sha = stem
            source_path_str = str(target.resolve())
        else:
            sha = sha256(target)
            source_path_str = str(target.resolve())

        sample_report: Dict[str, Any] = {
            "schema": "rexis.llmrag.report.v1",
            "run_name": run_name,
            "generated_at": now_iso(),
            "sample": {
                "sha256": sha,
                "source_path": source_path_str,
            },
            "program": {},
            "artifacts": {
                "features_path": None,
                "llmrag_path": None,
                "retrieval": [],
            },
            "llmrag": {
                "score": 0.0,
                "label": "unknown",
                "families": [],
                "capabilities": [],
                "tactics": [],
                "evidence": [],
                "uncertainty": "high",
            },
            "final": {
                "score": 0.0,
                "label": "unknown",
            },
            "audit": (
                [
                    {
                        "ts": now_iso(),
                        "event": "stub_start",
                        "detail": {"note": "LLM+RAG pipeline not implemented yet"},
                    },
                    {"ts": now_iso(), "event": "stub_end"},
                ]
                if audit
                else []
            ),
        }

        sample_report_path = run_dir / f"{sha}.report.json"
        write_json(sample_report, sample_report_path)
        print(f"LLM+RAG report: {sample_report_path}")
        if audit:
            run_audit.append(
                {
                    "ts": now_iso(),
                    "event": "sample_report_written",
                    "sha256": sha,
                    "path": str(sample_report_path),
                }
            )
        return sample_report_path

    try:
        if len(targets) == 1:
            print("Processing single file")
            primary_output = _worker(targets[0])
        else:
            if parallel > 1:
                print(f"Batch mode: processing {len(targets)} files with parallel={parallel}")
                with concurrent.futures.ProcessPoolExecutor(max_workers=parallel) as ex:
                    for path in ex.map(_worker, targets):
                        reports.append(path)
            else:
                print(f"Batch mode: processing {len(targets)} files sequentially")
                for t in targets:
                    reports.append(_worker(t))

            # Summary (baseline-like)
            summary: Dict[str, Any] = {
                "schema": "rexis.llmrag.summary.v1",
                "run_id": run_name,
                "generated_at": now_iso(),
                "inputs_root": str(input_path.resolve()),
                "count": len(targets),
                "reports": [str(p) for p in reports],
                "out_dir": str(run_dir.resolve()),
            }
            summary_path: Path = run_dir / "llmrag_summary.json"
            write_json(summary, summary_path)
            print(f"Batch summary written: {summary_path}")
            if audit:
                run_audit.append(
                    {"ts": now_iso(), "event": "summary_written", "path": str(summary_path)}
                )
            primary_output = summary_path
    except Exception as e:
        LOGGER.error("LLM+RAG pipeline failed: %s", e)
        print(f"LLM+RAG pipeline failed: {e}")
        status = "error"
        error_message = str(e)
        exc = e
    else:
        exc = None

    end_ts: float = time.time()
    ended_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts))
    duration_sec: float = round(end_ts - start_ts, 3)

    if audit:
        run_audit.append({"ts": now_iso(), "event": "run_end"})

    # Run-level report (baseline-like)
    run_report: Dict[str, Any] = {
        "run_id": run_name,
        "base_path": base_path,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": duration_sec,
        "status": status,
        "error": error_message,
        "inputs": {
            "input_path": str(input_path.resolve()),
            "parallel": parallel,
            "report_format": report_format,
            "project_dir": str(project_dir) if project_dir else None,
            "audit": audit,
        },
        "outputs": {
            "primary": str(primary_output) if primary_output else None,
            "reports": [str(p) for p in reports] if reports else None,
            "run_dir": str(run_dir),
        },
        "environment": {
            "rexis_version": get_version(),
        },
        "audit": run_audit if audit else [],
    }
    run_report_path: Path = run_dir / f"{base_path}.report.json"
    try:
        write_json(run_report, run_report_path)
        LOGGER.info(f"Run report written to {run_report_path}")
    except Exception as re:
        LOGGER.error("Failed to write run report %s: %s", run_report_path, re)

    if exc:
        raise exc

    assert primary_output is not None
    return primary_output, run_report_path
