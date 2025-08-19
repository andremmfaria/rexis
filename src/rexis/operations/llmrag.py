from pathlib import Path
from typing import Tuple


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
    Orchestrates the mml+rag pipeline for a file or directory.
    Returns (primary_output_path, run_report_path):
      - primary_output_path: single-file -> <sha256>.report.json; directory -> mmlrag_summary.json
      - run_report_path:     <run_base>.report.json with inputs/outputs summary (like decompile.py)
    """
    
    print(f"[LLM+RAG] Executing analysis for {input_path} (run={run_name}) → out={out_dir}")

    return out_dir / f"{run_name}.report.json", out_dir / f"{run_name}.summary.json"
