import uuid
from pathlib import Path

import typer
from rexis.cli.utils import format_validator, severity_validator
from rexis.operations.baseline import analyze_baseline_exec


def cmd_analyze_baseline(
    # INPUT
    input_path: Path = typer.Option(
        ...,
        "--input",
        "-i",
        exists=True,
        dir_okay=True,
        file_okay=True,
        readable=True,
        help="file or directory to analyze",
    ),
    # OUTPUT / RUN CONTEXT
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all artifacts (features, reports). Defaults to current working directory.",
    ),
    run_name: str | None = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this run. Defaults to a UUID if omitted.",
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", "-y", help="Overwrite existing artifacts when present"
    ),
    format: str = typer.Option(
        "json", "--format", "-f", callback=format_validator, help="Report format (default: json)"
    ),
    # GHIDRA / DECOMPILER
    project_dir: Path | None = typer.Option(
        Path.home() / ".rexis" / "ghidra_projects",
        "--project-dir",
        "-d",
        help="Ghidra project store (default: ~/.rexis/ghidra_projects)",
    ),
    parallel: int = typer.Option(
        1, "--parallel", "-p", help="Process multiple files in parallel (dir input only)"
    ),
    # HEURISTICS
    rules: Path | None = typer.Option(None, "--rules", help="Heuristic rules file (YAML/JSON)"),
    min_severity: str = typer.Option(
        "info",
        "--min-severity",
        "-m",
        callback=severity_validator,
        help="Filter heuristic evidence: info|warn|error",
    ),
    # VIRUSTOTAL (optional enrichment)
    vt: bool = typer.Option(False, "--vt", help="Enable VirusTotal enrichment"),
    vt_timeout: int = typer.Option(20, "--vt-timeout", help="Timeout for VT HTTP calls (seconds)"),
    vt_rate_limit_qpm: int = typer.Option(240, "--vt-qpm", help="VT queries per minute budget"),
    # LOGGING / AUDIT
    audit: bool = typer.Option(True, "--audit/--no-audit", help="Include audit trail in report"),
) -> None:
    """
    Baseline pipeline (decompile → heuristics → optional VT → report).

    If INPUT_PATH is a file: runs the pipeline for a single sample.
    If INPUT_PATH is a directory: recursively discovers PE files (.exe/.dll/.sys) and batches them.
    Outputs:
      - <sha256>.features.json    (decompiler features)
      - <sha256>.baseline.json    (heuristic classification)
      - <sha256>.report.json      (final report with optional VT enrichment)
      - baseline_summary.json     (batch summary when INPUT_PATH is a directory)
    """
    run_name_str: str = f"baseline-analysis-{run_name or uuid.uuid4().hex}"
    primary_path, run_report_path = analyze_baseline_exec(
        input_path=input_path,
        out_dir=out_dir,
        run_name=run_name_str,
        overwrite=overwrite,
        report_format=format,
        # decompiler
        project_dir=project_dir,
        parallel=parallel,
        # heuristics
        rules_path=rules,
        min_severity=min_severity,
        # virustotal
        vt_enabled=vt,
        vt_timeout=vt_timeout,
        vt_qpm=vt_rate_limit_qpm,
        # audit
        audit=audit,
    )

    typer.echo(f"Primary output: {primary_path}\nRun report: {run_report_path}")
