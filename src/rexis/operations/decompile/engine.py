from typing import Any, Iterable, List

from rexis.utils.types import DecompiledFunction
from rexis.utils.utils import LOGGER

DecompInterface = None  # lazy


def ensure_decompiler_loaded() -> None:
    global DecompInterface
    if DecompInterface is None:
        try:
            from ghidra.app.decompiler import DecompInterface as _DecompInterface  # type: ignore

            DecompInterface = _DecompInterface  # type: ignore
        except Exception:
            pass


def decompile_all_functions(program: Any, timeout_sec: int = 30) -> List[DecompiledFunction]:
    """Decompile every function and return C-like pseudocode."""
    ensure_decompiler_loaded()
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
    return results
