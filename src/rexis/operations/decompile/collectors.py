import math
from typing import Any, Iterable, List

from rexis.utils.types import FunctionInfo, MemorySection
from rexis.utils.utils import LOGGER

# Public constants
MAX_SECTION_SAMPLE_BYTES = 262_144  # 256 KiB


def collect_functions(program: Any) -> List[FunctionInfo]:
    listing: Any = program.getListing()
    results: List[FunctionInfo] = []
    for f in listing.getFunctions(True):
        try:
            results.append(
                {
                    "name": f.getName(),
                    "entry": str(f.getEntryPoint()),
                    "size": f.getBody().getNumAddresses(),
                    "is_thunk": bool(getattr(f, "isThunk", lambda: False)()),
                    "calling_convention": (
                        f.getCallingConventionName() if hasattr(f, "getCallingConventionName") else None
                    ),
                }
            )
        except Exception as e:
            LOGGER.error("Skipping function %s due to error: %s", f.getName(), e)
    return results


def collect_imports(program: Any, SymbolType: Any) -> List[str]:
    if SymbolType is None:
        LOGGER.warning("SymbolType not available; skipping import collection.")
        return []
    imports: List[str] = []
    st: Any = program.getSymbolTable()
    for s in st.getExternalSymbols():
        try:
            if s.getSymbolType() == SymbolType.FUNCTION:
                imports.append(s.getName())
        except Exception as e:
            LOGGER.error("Error collecting import %s: %s", s.getName(), e)
    return sorted(set(imports))


def collect_sections(program: Any) -> List[MemorySection]:
    sections: List[MemorySection] = []
    try:
        memory: Any = program.getMemory()
        fm: Any = program.getFunctionManager()
        func_entries: List[Any] = []
        try:
            for f in fm.getFunctions(True):
                try:
                    func_entries.append(f.getEntryPoint())
                except Exception:
                    pass
        except Exception:
            pass

        for block in memory.getBlocks():
            try:
                sec: MemorySection = {
                    "name": block.getName(),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": int(block.getSize()),
                    "initialized": bool(block.isInitialized()),
                    "read": bool(block.isRead()),
                    "write": bool(block.isWrite()),
                    "execute": bool(block.isExecute()),
                    "volatile": bool(block.isVolatile()),
                    "overlay": bool(block.isOverlay()),
                    "loaded": bool(block.isLoaded()),
                }
                if hasattr(block, "getType"):
                    try:
                        sec["type"] = str(block.getType())
                    except Exception:
                        sec["type"] = None
                if hasattr(block, "getSourceName"):
                    try:
                        sec["source_name"] = block.getSourceName()
                    except Exception:
                        sec["source_name"] = None
                if hasattr(block, "getComment"):
                    try:
                        sec["comment"] = block.getComment()
                    except Exception:
                        sec["comment"] = None

                total_size = int(block.getSize())
                sample_len = min(total_size, MAX_SECTION_SAMPLE_BYTES)
                bytes_truncated = total_size > sample_len
                sample_bytes = bytearray(sample_len)
                bytes_read = 0
                try:
                    bytes_read = memory.getBytes(block.getStart(), sample_bytes) or 0
                    if bytes_read < sample_len:
                        sample_bytes = sample_bytes[:max(0, bytes_read)]
                except Exception as read_err:
                    LOGGER.error("Failed reading block bytes for %s: %s", sec["name"], read_err)
                    sample_bytes = bytearray()
                    bytes_read = 0

                entropy_value = 0.0
                if sample_bytes:
                    try:
                        counts = [0] * 256
                        for byte_val in sample_bytes:
                            counts[byte_val & 0xFF] += 1
                        total = float(len(sample_bytes))
                        entropy_sum = 0.0
                        for cnt in counts:
                            if cnt:
                                p = cnt / total
                                entropy_sum -= p * math.log(p, 2)
                        entropy_value = round(entropy_sum, 4)
                    except Exception:
                        entropy_value = 0.0

                def _count_ascii_strings(data: bytes, min_len: int = 4) -> int:
                    count = 0
                    run = 0
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

                def _count_utf16le_strings(data: bytes, min_len: int = 4) -> int:
                    count = 0
                    run = 0
                    limit = len(data) - 1
                    i = 0
                    while i < limit:
                        low = data[i]
                        high = data[i + 1]
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

                strings_count = 0
                if sample_bytes:
                    try:
                        data_bytes = bytes(sample_bytes)
                        strings_count = _count_ascii_strings(data_bytes) + _count_utf16le_strings(data_bytes)
                    except Exception:
                        strings_count = 0

                functions_count = 0
                try:
                    for entry_addr in func_entries:
                        try:
                            if block.contains(entry_addr):
                                functions_count += 1
                        except Exception:
                            pass
                except Exception:
                    functions_count = 0

                sec["entropy"] = float(entropy_value)
                sec["strings_count"] = int(strings_count)
                sec["functions_count"] = int(functions_count)
                sec["bytes_total"] = int(total_size)
                sec["bytes_sampled"] = int(bytes_read)
                sec["bytes_truncated"] = bool(bytes_truncated)

                sections.append(sec)
            except Exception as block_err:
                try:
                    block_name = block.getName()
                except Exception:
                    block_name = "<unknown>"
                LOGGER.error("Error collecting section %s: %s", block_name, block_err)
    except Exception as e:
        LOGGER.error("Failed to iterate memory blocks: %s", e)

    sections.sort(key=lambda s: s.get("start", ""))
    return sections


def collect_libraries(program: Any) -> List[str]:
    libraries: List[str] = []
    try:
        em = program.getExternalManager()
        try:
            for nm in em.getExternalLibraryNames():
                try:
                    libraries.append(str(nm))
                except Exception:
                    pass
        except Exception:
            pass
        if not libraries:
            try:
                st = program.getSymbolTable()
                sset = set()
                for s in st.getExternalSymbols():
                    try:
                        ns = s.getParentNamespace()
                        if ns is not None:
                            sset.add(str(ns.getName()))
                    except Exception:
                        pass
                libraries = sorted(sset)
            except Exception:
                libraries = []
    except Exception:
        libraries = []
    return libraries


def collect_exports(program: Any, SymbolType: Any) -> List[str]:
    exports: List[str] = []
    try:
        st = program.getSymbolTable()
        for s in st.getAllSymbols(True):
            try:
                if getattr(s, "isExternal", lambda: False)():
                    continue
                if getattr(s, "isGlobal", lambda: False)():
                    if SymbolType is None or s.getSymbolType() == SymbolType.FUNCTION:
                        exports.append(s.getName())
            except Exception:
                pass
    except Exception:
        exports = []
    try:
        exports = sorted(set(exports))
    except Exception:
        pass
    return exports


def collect_entry_points(program: Any) -> List[str]:
    entry_points: List[str] = []
    try:
        ep = program.getProgramEntryPoint()
        if ep is not None:
            entry_points.append(str(ep))
    except Exception:
        pass
    try:
        fm = program.getFunctionManager()
        for f in fm.getFunctions(True):
            try:
                if hasattr(f, "isEntryPoint") and f.isEntryPoint():
                    entry_points.append(str(f.getEntryPoint()))
            except Exception:
                pass
    except Exception:
        pass
    try:
        entry_points = sorted(set(entry_points))
    except Exception:
        pass
    return entry_points
