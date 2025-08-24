import math
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rexis.utils.utils import LOGGER

GHIDRA_LOADED_CLASSES: SimpleNamespace = SimpleNamespace(
    ConsoleTaskMonitor=None,
    AnalysisScheduler=None,
    DecompInterface=None,
)


def ensure_ghidra_imports_loaded() -> None:
    """Import Ghidra scheduler/monitor APIs once the JVM is up.

    Also loads SymbolType for use by collectors after the JVM has started.
    """
    global GHIDRA_LOADED_CLASSES
    if GHIDRA_LOADED_CLASSES.ConsoleTaskMonitor is None:
        try:
            from ghidra.util.task import ConsoleTaskMonitor as _ConsoleTaskMonitor  # type: ignore

            GHIDRA_LOADED_CLASSES.ConsoleTaskMonitor = _ConsoleTaskMonitor  # type: ignore
        except Exception:
            pass
    if GHIDRA_LOADED_CLASSES.AnalysisScheduler is None:
        try:
            from ghidra.app.services import AnalysisScheduler as _AnalysisScheduler  # type: ignore

            GHIDRA_LOADED_CLASSES.AnalysisScheduler = _AnalysisScheduler  # type: ignore
        except Exception:
            pass
    if GHIDRA_LOADED_CLASSES.DecompInterface is None:
        try:
            from ghidra.app.decompiler import DecompInterface as _DecompInterface  # type: ignore

            GHIDRA_LOADED_CLASSES.DecompInterface = _DecompInterface  # type: ignore
        except Exception:
            GHIDRA_LOADED_CLASSES.DecompInterface = None  # type: ignore


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
    try:
        ConsoleTaskMonitor = GHIDRA_LOADED_CLASSES.ConsoleTaskMonitor
        AnalysisScheduler = GHIDRA_LOADED_CLASSES.AnalysisScheduler
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


def count_ascii_strings(data: bytes, min_len: int = 4) -> int:
    count = run = 0
    for ch in data:
        if 32 <= ch <= 126:
            run += 1
        else:
            if run >= min_len:
                count += 1
            run = 0
    if run >= min_len:
        count += 1
    return count


def count_utf16le_strings(data: bytes, min_len: int = 4) -> int:
    count = run = 0
    i, limit = 0, len(data) - 1
    while i < limit:
        low, high = data[i], data[i + 1]
        if 32 <= low <= 126 and high == 0:
            run += 1
            i += 2
            continue
        if run >= min_len:
            count += 1
        run = 0
        i += 2
    if run >= min_len:
        count += 1
    return count


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = float(len(data))
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log(p, 2)
    return round(h, 4)


def read_bytes_slow(mem, start_addr, length: int) -> bytes:
    """Safe fallback for PyGhidra: read 'length' bytes byte-by-byte."""
    out = bytearray()
    addr = start_addr
    for _ in range(max(0, int(length))):
        if addr is None:
            break
        try:
            # getByte returns a signed Java byte; mask to 0..255
            out.append(mem.getByte(addr) & 0xFF)
            addr = addr.next()
        except Exception:
            # Stop on any address/memory read issue
            break
    return bytes(out)
