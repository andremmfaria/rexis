import hashlib
import importlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

import pyghidra
from rexis.utils.utils import LOGGER


def _require_ghidra_env():
    """Ensure Ghidra is installed at /opt/ghidra and make it available to PyGhidra.

    We assume a flat install with the 'support' folder at /opt/ghidra/support.
    """
    gid_path = Path("/opt/ghidra")
    if not gid_path.exists():
        raise RuntimeError("Ghidra not found at /opt/ghidra. Please install it there.")
    support = gid_path / "support"
    if not support.exists():
        raise RuntimeError(
            f"Invalid Ghidra install: missing 'support' folder at {support}."
        )


def _wait_for_analysis(program):
    """Ensure Ghidra analysis has run; safe to call repeatedly."""
    ghidra_task = importlib.import_module("ghidra.util.task")
    ghidra_services = importlib.import_module("ghidra.app.services")

    monitor = ghidra_task.ConsoleTaskMonitor()
    scheduler = ghidra_services.AnalysisScheduler.getAnalysisScheduler(program)
    scheduler.startAnalysis(monitor)
    # Busy-wait with a small sleep; inexpensive and avoids blocking UI tasks
    while scheduler.isAnalyzing(program):
        time.sleep(0.1)


def _collect_functions(program) -> List[Dict[str, object]]:
    listing = program.getListing()
    funcs = []
    it = listing.getFunctions(True)
    for f in it:
        try:
            funcs.append(
                {
                    "name": f.getName(),
                    "entry": str(f.getEntryPoint()),
                    "size": f.getBody().getNumAddresses(),
                }
            )
        except Exception:
            pass
    return funcs


def _collect_imports(program) -> List[str]:
    imports = []
    ghidra_symbol = importlib.import_module("ghidra.program.model.symbol")
    SymbolType = ghidra_symbol.SymbolType

    st = program.getSymbolTable()
    for s in st.getExternalSymbols():
        if s.getSymbolType() == SymbolType.FUNCTION:
            imports.append(s.getName())
    return sorted(set(imports))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def decompile_binary_exec(
    file: Path,
    out_dir: Path,
    overwrite: bool = False,
    project_dir: Optional[Path] = None,
    project_name: str = "rexis",
) -> Path:
    """Analyze a binary with PyGhidra and write features JSON.

    Args:
        file: Path to the binary to analyze.
        out_dir: Output directory for the JSON.
        overwrite: Whether to overwrite an existing output file.
        project_dir: Optional path to the local Ghidra project store. Default: ~/.rexis/ghidra_projects
        project_name: Ghidra project name to reuse between runs.

    Returns:
        Path to the written JSON file.

    Raises:
        RuntimeError: If Ghidra install at /opt/ghidra is missing/invalid.
        FileExistsError: If output exists and overwrite is False.
        FileNotFoundError: If the input file does not exist.
    """
    _require_ghidra_env()

    if not file.exists():
        raise FileNotFoundError(str(file))

    file = file.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if project_dir is None:
        project_dir = Path.home() / ".rexis" / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)

    file_hash = _sha256(file)
    out_path = out_dir / f"{file_hash}.features.json"
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output exists: {out_path}")

    LOGGER.info("Starting PyGhidra...")
    pyghidra.start(False)

    LOGGER.info("Opening Ghidra project at %s (name=%s)", project_dir, project_name)
    with pyghidra.open_project(str(project_dir), project_name) as project:
        program = (
            project.openProgram(str(file))
            if project.contains(str(file))
            else project.importProgram(str(file))
        )
        try:
            _wait_for_analysis(program)

            prog_info = {
                "name": program.getName(),
                "format": program.getExecutableFormat(),
                "language": str(program.getLanguage().getLanguageDescription()),
                "compiler": str(program.getCompilerSpec().getCompilerSpecDescription()),
                "image_base": str(program.getImageBase()),
                "size": file.stat().st_size,
                "sha256": file_hash,
            }
            features = {
                "program": prog_info,
                "functions": _collect_functions(program),
                "imports": _collect_imports(program),
            }

            with out_path.open("w") as f:
                json.dump(features, f, indent=2)
            LOGGER.info("Wrote features to %s", out_path)
            return out_path
        finally:
            program.release(True)
