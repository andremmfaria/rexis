import json
import os
import time
from pathlib import Path
from typing import Any, Iterable, List, Optional

import pyghidra
from rexis.utils.types import DecompiledFunction, Features, FunctionInfo, ProgramInfo
from rexis.utils.utils import LOGGER, sha256, get_version

# Lazy placeholders for Ghidra APIs; will be populated after pyghidra.start()
ConsoleTaskMonitor = None  # type: ignore[assignment]
AnalysisScheduler = None  # type: ignore[assignment]
SymbolType = None  # type: ignore[assignment]
DecompInterface = None  # type: ignore[assignment]


def _ensure_ghidra_imports_loaded() -> None:
    """Best-effort import of Ghidra APIs after pyghidra.start()."""
    global ConsoleTaskMonitor, AnalysisScheduler, SymbolType, DecompInterface
    if ConsoleTaskMonitor is None:
        try:
            from ghidra.util.task import ConsoleTaskMonitor as _ConsoleTaskMonitor  # type: ignore

            ConsoleTaskMonitor = _ConsoleTaskMonitor  # type: ignore
        except Exception:
            pass
    if AnalysisScheduler is None:
        try:
            from ghidra.app.services import AnalysisScheduler as _AnalysisScheduler  # type: ignore

            AnalysisScheduler = _AnalysisScheduler  # type: ignore
        except Exception:
            pass
    if SymbolType is None:
        try:
            from ghidra.program.model.symbol import SymbolType as _SymbolType  # type: ignore

            SymbolType = _SymbolType  # type: ignore
        except Exception:
            pass
    if DecompInterface is None:
        try:
            from ghidra.app.decompiler import DecompInterface as _DecompInterface  # type: ignore

            DecompInterface = _DecompInterface  # type: ignore
        except Exception:
            pass


def _require_ghidra_env() -> None:
    """
    Ensure Ghidra is installed at /opt/ghidra and available to PyGhidra.

    We assume a flat install with the 'support' folder at /opt/ghidra/support.
    Also ensures GHIDRA_INSTALL_DIR points to /opt/ghidra for bootstrap.
    """
    print("Checking Ghidra install at /opt/ghidra...")
    gid_path: Path = Path("/opt/ghidra")
    if not gid_path.exists():
        raise RuntimeError("Ghidra not found at /opt/ghidra. Please install it there.")
    support: Path = gid_path / "support"
    if not support.exists():
        raise RuntimeError(f"Invalid Ghidra install: missing 'support' folder at {support}.")
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(gid_path))
    print("Installation found. GHIDRA_INSTALL_DIR set to /opt/ghidra")


def _wait_for_analysis(program: Any) -> None:
    """
    Ensure Ghidra analysis has run; safe to call repeatedly.
    """
    print("Waiting for analysis to complete...")
    try:
        if ConsoleTaskMonitor is None or AnalysisScheduler is None:
            LOGGER.warning(
                "AnalysisScheduler or ConsoleTaskMonitor not available; skipping explicit analysis wait."
            )
            return
        monitor: Any = ConsoleTaskMonitor()  # type: ignore[operator]
        scheduler: Any = AnalysisScheduler.getAnalysisScheduler(program)  # type: ignore[operator]
        scheduler.startAnalysis(monitor)
        while scheduler.isAnalyzing(program):
            time.sleep(0.1)
        print("Analysis completed.")
    except Exception as e:
        LOGGER.error("Skipping explicit analysis wait due to error: %s", e)


def _collect_functions(program: Any) -> List[FunctionInfo]:
    print("Collecting functions...")
    listing: Any = program.getListing()
    funcs: List[FunctionInfo] = []
    it: Iterable[Any] = listing.getFunctions(True)
    for f in it:
        try:
            funcs.append(
                {
                    "name": f.getName(),
                    "entry": str(f.getEntryPoint()),
                    "size": f.getBody().getNumAddresses(),
                    "is_thunk": bool(getattr(f, "isThunk", lambda: False)()),
                    "calling_convention": (
                        f.getCallingConventionName()
                        if hasattr(f, "getCallingConventionName")
                        else None
                    ),
                }
            )
        except Exception as e:
            LOGGER.error("Skipping function %s due to error: %s", f.getName(), e)
            pass
    print(f"Collected {len(funcs)} functions.")
    return funcs


def _collect_imports(program: Any) -> List[str]:
    print("Collecting imports...")
    imports: List[str] = []
    if SymbolType is None:  # type: ignore
        LOGGER.warning("SymbolType not available; skipping import collection.")
        return []

    st: Any = program.getSymbolTable()
    for s in st.getExternalSymbols():
        try:
            if s.getSymbolType() == SymbolType.FUNCTION:
                imports.append(s.getName())
        except Exception as e:
            LOGGER.error("Error collecting import %s: %s", s.getName(), e)
            pass
    unique_imports: List[str] = sorted(set(imports))
    print(f"Collected {len(unique_imports)} imports.")
    return unique_imports


def _decompile_all_functions(program: Any, timeout_sec: int = 30) -> List[DecompiledFunction]:
    """
    Decompile every function with Ghidra's Decompiler and return C-like pseudocode.
    timeout_sec applies per-function.
    """
    print("Starting decompilation of all functions...")
    if DecompInterface is None:
        LOGGER.warning("DecompInterface not available; skipping decompilation.")
        return []

    decompiler: Any = DecompInterface()  # type: ignore[operator]
    if not decompiler.openProgram(program):
        LOGGER.warning("Decompiler failed to open the program; skipping decompilation.")
        return []

    results: List[DecompiledFunction] = []
    fm: Any = program.getFunctionManager()
    funcs: Iterable[Any] = fm.getFunctions(True)

    for func in funcs:
        try:
            res: Any = decompiler.decompileFunction(func, timeout_sec, None)
            c_text: str = (
                res.getDecompiledFunction().getC() if res and res.decompileCompleted() else ""
            )
            results.append(
                {"name": func.getName(), "entry": str(func.getEntryPoint()), "c": c_text}
            )
        except Exception as e:
            LOGGER.error("Decompile error on %s: %s", func.getName(), e)
            results.append(
                {
                    "name": func.getName(),
                    "entry": str(func.getEntryPoint()),
                    "c": "",
                    "error": str(e),
                }
            )
    print(f"Decompilation complete. Functions processed: {len(results)}.")
    return results


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
    started_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(start_ts))

    if not file.exists():
        raise FileNotFoundError(str(file))

    base = f"{run_name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(start_ts))}"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir: Path = out_dir / base
    run_dir.mkdir(parents=True, exist_ok=True)

    file = file.resolve()
    if project_dir is None:
        project_dir = Path.home() / ".rexis" / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)

    # Prepare paths
    file_hash: str = sha256(file)
    out_path: Path = run_dir / f"{file_hash}.features.json"
    report_path: Path = run_dir / f"{base}.report.json"
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output exists: {out_path}")

    # Start PyGhidra here (after verifying env), then load Java APIs
    status = "success"
    error_message: Optional[str] = None
    features: Optional[Features] = None
    try:
        _require_ghidra_env()
        print("Starting PyGhidra...")
        pyghidra.start()
        _ensure_ghidra_imports_loaded()

        print(
            f"Opening Ghidra project at {project_dir} (name={project_name}). This might take some time. Please be patient."
        )
        with pyghidra.open_program(
            str(file),
            project_location=str(project_dir),
            project_name=project_name,
            analyze=True,
            nested_project_location=True,
        ) as flat_api:
            program: Any = flat_api.getCurrentProgram()

            _wait_for_analysis(program)

            prog_info: ProgramInfo = {
                "name": program.getName(),
                "format": program.getExecutableFormat(),
                "language": str(program.getLanguage().getLanguageDescription()),
                "compiler": str(program.getCompilerSpec().getCompilerSpecDescription()),
                "image_base": str(program.getImageBase()),
                "size": file.stat().st_size,
                "sha256": file_hash,
            }

            print("Collecting features (functions, imports, decompiled)...")
            functions: List[FunctionInfo] = _collect_functions(program)
            imports: List[str] = _collect_imports(program)
            decompiled: List[DecompiledFunction] = _decompile_all_functions(program, timeout_sec=30)

            features = {
                "program": prog_info,
                "functions": functions,
                "imports": imports,
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
        ended_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(end_ts))
        duration_sec = round(end_ts - start_ts, 3)
        summary = {
            "functions_count": len(features["functions"]) if features else None,
            "imports_count": len(features["imports"]) if features else None,
            "decompiled_count": len(features["decompiled"]) if features else None,
        }
        report = {
            "run_name": run_name,
            "base": base,
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

    if exc:
        raise exc
    return out_path, report_path
