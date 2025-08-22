import uuid
from pathlib import Path
import typer

from rexis.cli.utils import format_validator, severity_validator
from rexis.operations.baseline import analyze_baseline_exec
from rexis.operations.llmrag import analyze_llmrag_exec


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
    run_name_str: str = run_name or uuid.uuid4().hex
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

    typer.echo(
        f"[baseline] Baseline report: {primary_path}\n[baseline] Run report: {run_report_path}"
    )


def cmd_analyze_llmrag(
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
        "json",
        "--format",
        "-f",
        callback=format_validator,
        help="Report format (default: json)",
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
    # --- RAG knobs ---
    top_k_dense: int = typer.Option(
        50, "--top-k-dense", "-td", help="Top-k for dense (semantic) retriever"
    ),
    top_k_keyword: int = typer.Option(
        50, "--top-k-keyword", "-tk", help="Top-k for keyword (lexical) retriever"
    ),
    final_top_k: int = typer.Option(
        8, "--final-top-k", "-fk", help="How many passages to send to the LLM"
    ),
    join_mode: str = typer.Option(
        "rrf",
        "--join",
        "-j",
        help="How to fuse dense + keyword results: rrf|merge",
        show_default=True,
    ),
    rerank_top_k: int = typer.Option(
        0,
        "--rerank-top-k",
        "-rk",
        help="How many fused docs to pass through the cross-encoder ranker before selecting final_top_k. 0 (zero) means no reranking. (Default: 0)",
    ),
    ranker_model: str = typer.Option(
        "gpt-4o-mini",
        "--ranker-model",
        "-rm",
        help="Cross-encoder re-ranker model id",
        show_default=True,
    ),
    source_filter: list[str] = typer.Option(
        [],
        "--source",
        "-s",
        help="Repeatable. Restrict retrieval to these sources (e.g., --source malpedia --source vendor)",
    ),
    # --- LLM generator knobs ---
    model: str = typer.Option(
        "gpt-4o-mini",
        "--model",
        "-m",
        help="Generator model identifier",
        show_default=True,
    ),
    temperature: float = typer.Option(
        0.0, "--temperature", "-t", help="LLM temperature", show_default=True
    ),
    max_tokens: int = typer.Option(
        800, "--max-tokens", "-mt", help="Max tokens in LLM response", show_default=True
    ),
    seed: int = typer.Option(
        42, "--seed", "-sd", help="Randomness seed for the LLM (if supported)", show_default=True
    ),
    json_mode: bool = typer.Option(
        True, "--json-mode/--no-json-mode", "-jm/--no-jm", help="Force JSON-only response"
    ),
    # LOGGING / AUDIT
    audit: bool = typer.Option(
        True, "--audit/--no-audit", "-a/--no-a", help="Include audit trail in report"
    ),
) -> None:
    """
    LLM+RAG pipeline (features → hybrid retrieval → re-rank → LLM JSON → report).
    """
    run_name_str: str = run_name or uuid.uuid4().hex
    primary_path, run_report_path = analyze_llmrag_exec(
        input_path=input_path,
        out_dir=out_dir,
        run_name=run_name_str,
        overwrite=overwrite,
        report_format=format,
        # decompiler
        project_dir=project_dir,
        parallel=parallel,
        # rag
        top_k_dense=top_k_dense,
        top_k_keyword=top_k_keyword,
        final_top_k=final_top_k,
        join_mode=join_mode,
        rerank_top_k=rerank_top_k,
        ranker_model=ranker_model,
        source_filter=source_filter,
        # llm
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        seed=seed,
        json_mode=json_mode,
        # audit
        audit=audit,
    )
    typer.echo(f"[llmrag] LLMRAG report: {primary_path}\n[llmrag] Run report: {run_report_path}")
