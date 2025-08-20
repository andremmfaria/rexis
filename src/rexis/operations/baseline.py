import concurrent.futures
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rexis.operations.decompile.main import decompile_binary_exec
from rexis.tools.decision.main import fuse_heuristics_and_virustotal_decision
from rexis.tools.heuristics_analyser.main import heuristic_classify
from rexis.tools.heuristics_analyser.normal import families_from_vt_compact
from rexis.tools.heuristics_analyser.utils import get_nested_value, load_heuristic_rules
from rexis.tools.virus_total import query_virus_total
from rexis.utils.config import config
from rexis.utils.constants import DEFAULT_DECISION
from rexis.utils.types import VTConfig
from rexis.utils.utils import LOGGER, get_version, iter_pe_files, load_json, now_iso, write_json


class _SimpleRateLimiter:
    """
    Very small token-bucket-ish limiter based on QPM.
    Not perfect, but good enough for CLI batch runs.
    """

    _interval: float
    _last: float

    def __init__(self, qpm: int) -> None:
        self._interval = 60.0 / max(1, qpm)
        self._last = 0.0

    def wait(self) -> None:
        now: float = time.time()
        delta: float = now - self._last
        if delta < self._interval:
            time.sleep(self._interval - delta)
        self._last = time.time()


def _extract_sha256_from_features(features: Dict[str, Any], fallback_name: str = "") -> str:
    # prefer embedded sha256 written by your decompiler
    h: Optional[Any] = (features.get("program") or {}).get("sha256")
    if isinstance(h, str) and len(h) == 64:
        return h.lower()
    # last resort: derive from filename convention <sha256>.features.json
    if fallback_name.endswith(".features.json"):
        stem: str = Path(fallback_name).name.replace(".features.json", "")
        if len(stem) == 64:
            return stem.lower()
    raise ValueError("Could not determine sample sha256 from features")


def _vt_enrich_sha256(
    sha256: str,
    vt: VTConfig,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Query VirusTotal v3 for file metadata by SHA-256.
    Returns (vt_result_dict_or_none, error_message_or_none).
    """
    if not vt.enabled:
        return None, None
    if not vt.api_key:
        return None, "VT enabled but no API key provided"

    try:
        # Use vt-py based helper and compact the result to attributes-like view
        data: Dict[str, Any] = query_virus_total(hash=sha256, api_key=vt.api_key)
        attrs: Dict[str, Any] = data.get("attributes") or {}
        vt_compact: Dict[str, Any] = {
            "sha256": attrs.get("sha256") or sha256,
            "size": attrs.get("size"),
            "names": attrs.get("names"),
            "tags": attrs.get("tags"),
            "type_tags": attrs.get("type_tags"),
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
            "harmless": (attrs.get("last_analysis_stats") or {}).get("harmless"),
            "malicious": (attrs.get("last_analysis_stats") or {}).get("malicious"),
            "suspicious": (attrs.get("last_analysis_stats") or {}).get("suspicious"),
            "undetected": (attrs.get("last_analysis_stats") or {}).get("undetected"),
            "popular_threat_category": (attrs.get("popular_threat_classification") or {}).get(
                "popular_threat_category"
            ),
            "popular_threat_name": (attrs.get("popular_threat_classification") or {}).get(
                "popular_threat_name"
            ),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_submission_date": attrs.get("last_submission_date"),
        }
        return vt_compact, None
    except Exception as e:
        LOGGER.error("VirusTotal query failed: %s", e)
        return None, f"VT error: {e}"


def _process_sample(
    binary: Path,
    out_dir: Path,
    run_name: Optional[str],
    overwrite: bool,
    # decompiler
    project_dir: Optional[Path],
    # heuristics
    rules_path: Optional[Path],
    min_severity: str,
    # vt
    vt_cfg: VTConfig,
    vt_rate_limiter: Optional[_SimpleRateLimiter],
    # audit
    audit: bool,
) -> Path:
    """
    Run the full baseline pipeline for a single file and return the final report path.
    Produces:
      - <sha256>.features.json
      - <sha256>.baseline.json
      - <sha256>.report.json
    """
    started: float = time.time()
    audit_log: List[Dict[str, Any]] = []

    def _audit(event: str, **fields: Any) -> None:
        if audit:
            item: Dict[str, str] = {"ts": now_iso(), "event": event}
            item.update(fields)
            audit_log.append(item)

    _audit("pipeline_start", run_name=run_name, file=str(binary))
    print(f"[baseline] Analyzing file: {binary}")

    # 1) Decompile
    _audit("decompile_start")
    print("[baseline] Decompiling with Ghidra pipeline...")
    features_path: Path
    features_path, _ = decompile_binary_exec(
        file=binary,
        out_dir=out_dir,
        overwrite=overwrite,
        project_dir=project_dir,
        project_name="rexis",
        run_name=run_name,
    )
    _audit("decompile_done", features=str(features_path))

    # Load features
    features: Dict[str, Any] = load_json(features_path)
    sha256: str = _extract_sha256_from_features(features, features_path.name)
    print(f"[baseline] Binary analysis complete. Features loaded. sha256={sha256}")

    # 2) Heuristics
    _audit("heuristics_start")
    print("[baseline] Running heuristics...")
    heur: Dict[str, Any] = heuristic_classify(
        features=features, rules_path=rules_path, min_severity=min_severity
    )
    baseline_path: Path = out_dir / f"{sha256}.baseline.json"
    write_json(heur, baseline_path)
    _audit("heuristics_done", baseline=str(baseline_path))
    print(f"[baseline] Heuristics report: {baseline_path}")

    # 3) Optional VirusTotal enrichment
    vt_result: Optional[Dict[str, Any]] = None
    vt_error: Optional[str] = None
    if vt_cfg.enabled:
        if vt_rate_limiter:
            vt_rate_limiter.wait()
        _audit("vt_start")
        print("[baseline] Querying VirusTotal for enrichment...")
        vt_result, vt_error = _vt_enrich_sha256(sha256, vt_cfg)
        _audit("vt_done", ok=vt_error is None, error=vt_error)
        if vt_error:
            print(f"[baseline] VirusTotal enrichment error: {vt_error}")
        else:
            print("[baseline] VirusTotal enrichment complete.")

    # 4) Decision fusion (heuristics + VirusTotal) and taxonomy. Load heuristics config for decision defaults/overrides
    try:
        rules_cfg = load_heuristic_rules(rules_path)
    except Exception:
        rules_cfg = {}
    # Resolve decision settings from config with constants fallback
    d_weights = get_nested_value(rules_cfg, "decision.weights", DEFAULT_DECISION["weights"])  # type: ignore[index]
    d_thresholds = get_nested_value(rules_cfg, "decision.thresholds", DEFAULT_DECISION["thresholds"])  # type: ignore[index]
    d_policy = get_nested_value(rules_cfg, "decision.policy", DEFAULT_DECISION["policy"])  # type: ignore[index]

    fusion: Dict[str, Any] = fuse_heuristics_and_virustotal_decision(
        heuristics=heur,
        vt=vt_result,
        vt_error=vt_error,
        weights=d_weights,
        thresholds=d_thresholds,
        policy=d_policy,
    )

    # Vendor taxonomy harmonization. Load heuristics config to drive taxonomy normalization rules (reuses rules_cfg)
    families = families_from_vt_compact(vt_result or {}, rules_cfg=rules_cfg) if vt_result else {}
    # Include tags inferred by heuristics (already scored) as another taxonomy hint
    tags = heur.get("tags") or []

    report: Dict[str, Any] = {
        "schema": "rexis.baseline.report.v1",
        "run_id": run_name,
        "generated_at": now_iso(),
        "duration_sec": round(time.time() - started, 3),
        "sample": {
            "sha256": sha256,
            "source_path": str(binary.resolve()),
        },
        "artifacts": {
            "features_path": str(features_path),
            "baseline_path": str(baseline_path),
        },
        "program": features.get("program", {}),
        "taxonomy": {
            "families": families,  # canonical family counts from VT names
            "tags": tags,  # inferred tags from heuristics
        },
        "final": fusion.get("final", {}),
        "decision": fusion,
        "heuristics": heur,  # includes evidence, score, label, tags
        "virus_total": {"data": vt_result, "error": vt_error} if vt_cfg.enabled else {},
        "audit": audit_log if audit else [],
    }

    report_path: Path = out_dir / f"{sha256}.report.json"
    write_json(report, report_path)
    LOGGER.info(f"Decompilation report written to {report_path}")
    _audit("pipeline_done", report=str(report_path))
    return report_path


def analyze_baseline_exec(
    input_path: Path,
    out_dir: Path,
    run_name: Optional[str],
    overwrite: bool,
    report_format: str,
    # decompiler
    project_dir: Optional[Path],
    parallel: int,
    # heuristics
    rules_path: Optional[Path],
    min_severity: str,
    # virustotal
    vt_enabled: bool,
    vt_timeout: int,
    vt_qpm: int,
    # audit
    audit: bool,
) -> Tuple[Path, Path]:
    """
    Orchestrates the baseline pipeline for a file or directory.
    Returns (primary_output_path, run_report_path):
      - primary_output_path: single-file -> <sha256>.report.json; directory -> baseline_summary.json
      - run_report_path:     <run_base>.report.json with inputs/outputs summary (like decompile.py)
    """
    if report_format.lower() != "json":
        raise ValueError("Only 'json' report format is currently supported")

    # Create a per-run directory to align with decompile.py layout
    start_ts: float = time.time()
    started_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))
    base_path: str = f"baseline-analysis-{run_name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir: Path = out_dir / base_path
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"[baseline] Starting baseline analysis (run={run_name}) -> {run_dir}")

    # Determine targets
    targets: List[Path]
    if input_path.is_dir():
        targets = iter_pe_files(input_path)
        if not targets:
            raise FileNotFoundError(f"No PE files found under: {input_path}")
        print(f"[baseline] Discovered {len(targets)} PE file(s) under {input_path}")
    else:
        targets = [input_path]

    vt_cfg: VTConfig = VTConfig(
        enabled=vt_enabled,
        api_key=config.baseline.virus_total_api_key,
        qpm=max(1, vt_qpm),
    )
    vt_rate_limiter: Optional[_SimpleRateLimiter] = (
        _SimpleRateLimiter(vt_cfg.qpm) if vt_cfg.enabled else None
    )
    print(
        "[baseline] VirusTotal enrichment: "
        + (f"ENABLED (qpm={vt_cfg.qpm})" if vt_cfg.enabled else "disabled")
    )

    # Worker wrapper to pass through fixed parameters
    def _worker(binary: Path) -> Path:
        try:
            return _process_sample(
                binary=binary,
                out_dir=run_dir,
                run_name=run_name,
                overwrite=overwrite,
                project_dir=project_dir,
                rules_path=rules_path,
                min_severity=min_severity,
                vt_cfg=vt_cfg,
                vt_rate_limiter=vt_rate_limiter,
                audit=audit,
            )
        except Exception as e:
            LOGGER.error("Failed pipeline on %s: %s", binary, e)
            # Emit a minimal failure report to keep batch consistent
            fail_report: Dict[str, Any] = {
                "schema": "rexis.baseline.report.v1",
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
            primary_output = _worker(targets[0])
        else:
            # Batch mode
            if parallel > 1:
                print(f"[baseline] Batch mode: processing {len(targets)} files with parallel={parallel}")
                with concurrent.futures.ProcessPoolExecutor(max_workers=parallel) as ex:
                    for path in ex.map(_worker, targets):
                        reports.append(path)
            else:
                print(f"[baseline] Batch mode: processing {len(targets)} files sequentially")
                for t in targets:
                    reports.append(_worker(t))

            # Summary
            summary: Dict[str, Any] = {
                "schema": "rexis.baseline.summary.v1",
                "run_id": run_name,
                "generated_at": now_iso(),
                "inputs_root": str(input_path.resolve()),
                "count": len(targets),
                "reports": [str(p) for p in reports],
                "out_dir": str(run_dir.resolve()),
            }
            summary_path: Path = run_dir / "baseline_summary.json"
            write_json(summary, summary_path)
            print(f"[baseline] Batch summary written: {summary_path}")
            primary_output = summary_path
    except Exception as e:
        LOGGER.error("Pipeline failed: %s", e)
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
            "rules_path": str(rules_path) if rules_path else None,
            "min_severity": min_severity,
            "vt_enabled": vt_enabled,
            "vt_timeout": vt_timeout,
            "vt_qpm": vt_qpm,
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
        # If we failed before setting primary_output, ensure it's a Path to the run report
        raise exc

    # Single-file mode produced a report directly via worker; ensure we return it
    assert primary_output is not None
    return primary_output, run_report_path
