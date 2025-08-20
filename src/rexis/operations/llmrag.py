import concurrent.futures
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rexis.operations.decompile.main import decompile_binary_exec
from rexis.tools.llm_analyser.llm import llm_classify
from rexis.tools.llm_analyser.rag import build_queries_from_features, retrieve_context
from rexis.utils.utils import LOGGER, get_version, iter_pe_files, now_iso, sha256, write_json


def _decompile_target(
    target: Path,
    run_dir: Path,
    overwrite: bool,
    project_dir: Optional[Path],
    run_name: Optional[str],
) -> Tuple[str, Path, Dict[str, Any]]:
    """
    Returns (sha256, features_path, features_dict). If `target` is a PE, decompiles;
    if it's a <sha>.features.json, uses it directly.
    """
    if target.suffix.lower() == ".json" and target.name.endswith(".features.json"):
        features_path: Path = target
        # Try to infer sha from filename; else from JSON
        stem: str = target.name[: -len(".features.json")]
        if len(stem) == 64:
            h: str = stem.lower()
        else:
            with target.open("r", encoding="utf-8") as f:
                tmp: Dict[str, Any] = json.load(f)
            h = (tmp.get("program") or {}).get("sha256") or sha256(target)
        with target.open("r", encoding="utf-8") as f:
            features: Dict[str, Any] = json.load(f)
        return h, features_path, features

    print("[llmrag] Decompiling with Ghidra pipeline...")
    features_path, _ = decompile_binary_exec(
        file=target,
        out_dir=run_dir,
        overwrite=overwrite,
        project_dir=project_dir,
        project_name="rexis",
        run_name=run_name,
    )
    
    with features_path.open("r", encoding="utf-8") as f:
        features: Dict[str, Any] = json.load(f)
  
    hash: str = (features.get("program") or {}).get("sha256") or sha256(target)

    return hash, features_path, features


def _process_sample(
    target: Path,
    out_dir: Path,
    run_name: Optional[str],
    overwrite: bool,
    project_dir: Optional[Path],
    audit: bool,
) -> Path:
    """
    Process a single sample with the LLM+RAG stub flow and return the final report path.
    Produces per-sample artifacts:
      - <sha256>.llmrag.json
      - <sha256>.report.json
    """
    started: float = time.time()
    audit_log: List[Dict[str, Any]] = []

    def _audit(event: str, **fields: Any) -> None:
        if audit:
            item: Dict[str, Any] = {"ts": now_iso(), "event": event}
            item.update(fields)
            audit_log.append(item)

    print(f"[llmrag] Analyzing file: {target}")
    _audit("pipeline_start", run_name=run_name, file=str(target))

    # 1) Ensure features exist (use JSON or decompile a PE)
    _audit("decompile_start")
    sha256, features_path, features = _decompile_target(
        target=target,
        run_dir=out_dir,
        overwrite=overwrite,
        project_dir=project_dir,
        run_name=run_name,
    )
    _audit("decompile_ready", path=str(features_path))

    # 2) Build retrieval queries + (stub) retrieve context
    _audit("rag_start")
    queries: List[str] = build_queries_from_features(features)
    passages: List[Dict[str, Any]]
    rag_notes: Dict[str, Any] | str
    passages, rag_notes = retrieve_context(queries, top_k=8)
    _audit("rag_done", notes=rag_notes)

    # 3) (Stub) LLM classification using features + retrieved context
    _audit("llm_start")
    llm_out: Dict[str, Any] = llm_classify(features, passages)
    llmrag_path: Path = out_dir / f"{sha256}.llmrag.json"
    write_json(llm_out, llmrag_path)
    _audit("llm_done", path=str(llmrag_path))

    # Compute final label from score
    score: float = float(llm_out.get("score") or 0.0)
    if score >= 0.70:
        final_label: str = "malicious"
    elif score >= 0.40:
        final_label = "suspicious"
    else:
        final_label = (
            "benign" if llm_out.get("label") == "benign" else llm_out.get("label", "unknown")
        )

    program_block: Dict[str, Any] = (
        features.get("program", {}) if isinstance(features, dict) else {}
    )

    report: Dict[str, Any] = {
        "schema": "rexis.llmrag.report.v1",
        "run_name": run_name,
        "generated_at": now_iso(),
        "duration_sec": round(time.time() - started, 3),
        "sample": {"sha256": sha256, "source_path": str(target.resolve())},
        "program": program_block,
        "artifacts": {
            "features_path": str(features_path),
            "llmrag_path": str(llmrag_path),
            "retrieval": [
                {k: v for k, v in p.items() if k in {"doc_id", "source", "title", "score"}}
                for p in passages
            ],
        },
        "llmrag": llm_out,
        "final": {"score": round(score, 4), "label": final_label},
        "audit": audit_log if audit else [],
    }

    report_path: Path = out_dir / f"{sha256}.report.json"
    write_json(report, report_path)
    print(f"[llmrag] LLM+RAG report: {report_path}")
    _audit("pipeline_done", report=str(report_path))
    return report_path


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
    base_path: str = f"llmrag-analysis-{run_name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir: Path = out_dir / base_path
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"[llmrag] Starting llmrag analysis (run={run_name}) -> {run_dir}")

    # Determine targets (basic PE discovery for directory; single file otherwise)
    targets: List[Path]
    if input_path.is_dir():
        targets = iter_pe_files(input_path)
        if not targets:
            raise FileNotFoundError(f"No PE files found under: {input_path}")
        print(f"[llmrag] Discovered {len(targets)} PE file(s) under {input_path}")
    else:
        targets = [input_path]

    # Worker wrapper to pass through fixed parameters
    def _worker(binary: Path) -> Path:
        try:
            return _process_sample(
                target=binary,
                out_dir=run_dir,
                run_name=run_name,
                overwrite=overwrite,
                project_dir=project_dir,
                audit=audit,
            )
        except Exception as e:
            LOGGER.error("Failed LLM+RAG on %s: %s", binary, e)
            # Emit a minimal failure report to keep batch consistent
            fail_report: Dict[str, Any] = {
                "schema": "rexis.llmrag.report.v1",
                "run_id": run_name,
                "generated_at": now_iso(),
                "sample": {"source_path": str(binary.resolve())},
                "final": {"label": "error", "score": 0.0},
                "error": str(e),
            }
            safe_name: str = binary.name + ".error.report.json"
            fail_path: Path = run_dir / safe_name
            write_json(fail_report, fail_path)
            return fail_path

    # Execute
    status: str = "success"
    error_message: Optional[str] = None
    primary_output: Optional[Path] = None
    reports: List[Path] = []
    try:
        if len(targets) == 1:
            print("[llmrag] Processing single file")
            primary_output = _worker(targets[0])
        else:
            if parallel > 1:
                print(f"[llmrag] Batch mode: processing {len(targets)} files with parallel={parallel}")
                with concurrent.futures.ProcessPoolExecutor(max_workers=parallel) as ex:
                    for path in ex.map(_worker, targets):
                        reports.append(path)
            else:
                print(f"[llmrag] Batch mode: processing {len(targets)} files sequentially")
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
            print(f"[llmrag] Batch summary written: {summary_path}")
            primary_output = summary_path
    except Exception as e:
        LOGGER.error("LLM+RAG pipeline failed: %s", e)
        status = "error"
        error_message = str(e)
        exc = e
    else:
        exc = None

    end_ts: float = time.time()
    ended_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts))
    duration_sec: float = round(end_ts - start_ts, 3)
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
            "project_dir": str(project_dir) if project_dir else None,
        },
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
