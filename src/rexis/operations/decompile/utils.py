import os
from pathlib import Path
from typing import Any, List

from rexis.utils.utils import LOGGER

# Lazy placeholders populated after pyghidra.start()
ConsoleTaskMonitor = None  # type: ignore[assignment]
AnalysisScheduler = None  # type: ignore[assignment]
SymbolType = None  # type: ignore[assignment]


def ensure_ghidra_imports_loaded() -> None:
    """Import Ghidra scheduler/monitor APIs once the JVM is up.

    Also loads SymbolType for use by collectors after the JVM has started.
    """
    global ConsoleTaskMonitor, AnalysisScheduler, SymbolType
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
            SymbolType = None  # type: ignore


def require_ghidra_env() -> None:
    """Ensure a Ghidra install exists at /opt/ghidra and set env vars."""
    gid_path: Path = Path("/opt/ghidra")
    if not gid_path.exists():
        raise RuntimeError("Ghidra not found at /opt/ghidra. Please install it there.")
    support: Path = gid_path / "support"
    if not support.exists():
        raise RuntimeError(f"Invalid Ghidra install: missing 'support' folder at {support}.")
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(gid_path))


def wait_for_analysis(program: Any) -> None:
    """Block until program analysis completes (best-effort)."""
    global ConsoleTaskMonitor, AnalysisScheduler
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
            import time as _t

            _t.sleep(0.1)
    except Exception as e:
        LOGGER.error("Skipping explicit analysis wait due to error: %s", e)
