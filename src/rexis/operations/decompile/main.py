import json
import os
import time
from pathlib import Path
from typing import Any, List, Optional

import pyghidra
from rexis.operations.decompile.collectors import (
    collect_entry_points,
    collect_exports,
    collect_functions,
    collect_imports,
    collect_libraries,
    collect_sections,
)
from rexis.operations.decompile.engine import decompile_all_functions
from rexis.operations.decompile.utils import (
    ensure_ghidra_imports_loaded,
    require_ghidra_env,
    wait_for_analysis,
)
from rexis.utils.types import DecompiledFunction, Features, FunctionInfo, MemorySection, ProgramInfo
from rexis.utils.utils import LOGGER, get_version, sha256


def decompile_binary_exec(
    file: Path,
    out_dir: Path,
    overwrite: bool = False,
    project_dir: Optional[Path] = None,
    project_name: str = "rexis",
    run_name: Optional[str] = None,
) -> tuple[Path, Path]:
    """
    Analyze a binary with PyGhidra and write features + decompiled C to JSON.

    Args:
        file: Path to the binary to analyze.
        out_dir: Output directory for the JSON.
        overwrite: Whether to overwrite an existing output file.
        project_dir: Optional path to the local Ghidra project store. Default: ~/.rexis/ghidra_projects
        project_name: Ghidra project name to reuse between runs.

    Returns:
        Tuple of (features_json_path, report_json_path).
    """
    start_ts = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))

    if not file.exists():
        raise FileNotFoundError(str(file))

    base_path = f"decompile-{run_name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir: Path = out_dir / base_path
    run_dir.mkdir(parents=True, exist_ok=True)

    file = file.resolve()
    if project_dir is None:
        project_dir = Path.home() / ".rexis" / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)

    # Prepare paths
    file_hash: str = sha256(file)
    out_path: Path = run_dir / f"{file_hash}.features.json"
    report_path: Path = run_dir / f"{base_path}.report.json"
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output exists: {out_path}")

    # Start PyGhidra here (after verifying env), then load Java APIs
    status = "success"
    error_message: Optional[str] = None
    features: Optional[Features] = None
    try:
        print("[decompile] Validating Ghidra environment...")
        require_ghidra_env()
        print("[decompile] Starting PyGhidra...")
        pyghidra.start()
        print("[decompile] PyGhidra started.")

        # Ensure required Ghidra imports and load SymbolType in env
        ensure_ghidra_imports_loaded()
        print("[decompile] Ghidra imports loaded.")

        print(
            f"[decompile] Opening Ghidra project at {project_dir} (name={project_name}). This might take some time."
        )
        with pyghidra.open_program(
            str(file),
            project_location=str(project_dir),
            project_name=project_name,
            analyze=True,
            nested_project_location=True,
        ) as flat_api:
            program: Any = flat_api.getCurrentProgram()
            print("[decompile] Waiting for Ghidra analysis to complete...")
            wait_for_analysis(program)
            print("[decompile] Analysis complete.")

            prog_info: ProgramInfo = {
                "name": program.getName(),
                "format": program.getExecutableFormat(),
                "language": str(program.getLanguage().getLanguageDescription()),
                "compiler": str(program.getCompilerSpec().getCompilerSpecDescription()),
                "image_base": str(program.getImageBase()),
                "size": file.stat().st_size,
                "sha256": file_hash,
            }

            print(
                "[decompile] Collecting features (functions, imports, sections, libraries, exports, entry points, decompiled)..."
            )
            functions: List[FunctionInfo] = collect_functions(program)
            imports: List[str] = collect_imports(program)
            strings: List[str] = collect_strings(program)
            sections: List[MemorySection] = collect_sections(program)
            libraries: List[str] = collect_libraries(program)
            exports: List[str] = collect_exports(program)
            entry_points: List[str] = collect_entry_points(program)
            print(
                f"[decompile] Summary so far: functions={len(functions)}, imports={len(imports)}, strings={len(strings)}, sections={len(sections)}, libraries={len(libraries)}, exports={len(exports)}, entry_points={len(entry_points)}"
            )
            t0 = time.time()
            print("[decompile] Starting decompilation of functions (timeout=30s per function)...")
            decompiled: List[DecompiledFunction] = decompile_all_functions(program, timeout_sec=30)
            t1 = time.time()
            print(
                f"[decompile] Decompilation finished: decompiled={len(decompiled)} functions in {round(t1 - t0, 2)}s"
            )

            features: Features = {
                "program": prog_info,
                "functions": functions,
                "imports": imports,
                "strings": strings,
                "sections": sections,
                "libraries": libraries,
                "exports": exports,
                "entry_points": entry_points,
                "decompiled": decompiled,
            }

            with out_path.open("w") as f:
                json.dump(features, f, indent=2)

            LOGGER.info(f"Wrote features to {out_path}")
    except Exception as e:
        LOGGER.error("Decompilation failed: %s", e)
        status = "error"
        error_message = str(e)
        # Re-raise after writing report
        exc = e
    else:
        exc = None
    finally:
        end_ts = time.time()
        ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts))
        duration_sec = round(end_ts - start_ts, 3)
        print(f"[decompile] Preparing run report (status={status}, duration={duration_sec}s)...")
        summary = {
            "functions_count": len(features["functions"]) if features else None,
            "imports_count": len(features["imports"]) if features else None,
            "strings_count": (
                len(features["strings"]) if features and "strings" in features else None
            ),
            "sections_count": (
                len(features["sections"]) if features and "sections" in features else None
            ),
            "libraries_count": (
                len(features["libraries"]) if features and "libraries" in features else None
            ),
            "exports_count": (
                len(features["exports"]) if features and "exports" in features else None
            ),
            "entry_points_count": (
                len(features["entry_points"]) if features and "entry_points" in features else None
            ),
            "decompiled_count": len(features["decompiled"]) if features else None,
        }
        report = {
            "run_id": run_name,
            "base_path": base_path,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_sec,
            "status": status,
            "error": error_message,
            "summary": summary,
            "inputs": {
                "file": str(file),
            },
            "outputs": {
                "features_path": str(out_path),
                "run_dir": str(run_dir),
            },
            "environment": {
                "rexis_version": get_version(),
                "ghidra_install_dir": os.environ.get("GHIDRA_INSTALL_DIR"),
                "project_dir": str(project_dir),
                "project_name": project_name,
            },
        }
        try:
            with report_path.open("w") as rf:
                json.dump(report, rf, indent=2)

            LOGGER.info(f"Run report written to {report_path}")
        except Exception as re:
            LOGGER.error("Failed to write run report %s: %s", report_path, re)
            print(f"[decompile] Failed to write run report {report_path}: {re}")

    if exc:
        print(f"[decompile] Exiting with error: {error_message}")
        raise exc
    print(f"[decompile] Completed successfully in {duration_sec}s")
    return out_path, report_path
