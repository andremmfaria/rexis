import math
from typing import Any, List, Set

from rexis.operations.decompile.utils import DefinedStringsIterator, StringDataInstance
from rexis.utils.types import FunctionInfo, MemorySection
from rexis.utils.utils import LOGGER

# Public constants
MAX_SECTION_SAMPLE_BYTES = 262_144  # 256 KiB
# Strings collection limits
MIN_STRING_LEN = 4
MAX_STRING_LEN = 1024
MAX_STRINGS = 10000
MAX_BLOCK_SCAN_BYTES = 2 * 1024 * 1024  # scan up to 2 MiB per block (head and tail)


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
                        f.getCallingConventionName()
                        if hasattr(f, "getCallingConventionName")
                        else None
                    ),
                }
            )
        except Exception as e:
            LOGGER.error("Skipping function %s due to error: %s", f.getName(), e)
    return results


def collect_imports(program: Any) -> List[str]:
    """
    Collect names of external symbols as a proxy for imported APIs.
    Some Ghidra versions/types may not tag imports strictly as FUNCTION; be permissive.
    """
    imports: Set[str] = set()
    try:
        st: Any = program.getSymbolTable()
        for s in st.getExternalSymbols():
            try:
                name = s.getName()
                if name:
                    imports.add(str(name))
            except Exception:
                pass
    except Exception as e:
        LOGGER.error("Failed collecting external symbols: %s", e)
    return sorted(imports)


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
                        sample_bytes = sample_bytes[: max(0, bytes_read)]
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
                        strings_count = _count_ascii_strings(data_bytes) + _count_utf16le_strings(
                            data_bytes
                        )
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


def collect_exports(program: Any) -> List[str]:
    exports: List[str] = []
    try:
        st = program.getSymbolTable()
        for s in st.getAllSymbols(True):
            try:
                if getattr(s, "isExternal", lambda: False)():
                    continue
                if getattr(s, "isGlobal", lambda: False)():
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


def collect_strings(program: Any) -> List[str]:
    """
    Orchestrate string collection using three strategies:
    1) Byte-scan on initialized mem blocks
    2) Defined data walk
    3) DefinedStringsIterator
    """

    # Strategy 1
    try:
        s1 = collect_strings_bytescan(program)
    except Exception:
        s1 = []
    if s1:
        return s1

    # Strategy 2
    try:
        s2 = collect_strings_defined_data(program)
    except Exception:
        s2 = []
    if s2:
        return s2

    # Strategy 3
    return collect_strings_defined_iterator(program)


def _normalize_and_add(sset: Set[str], s: str) -> None:
    if not s:
        return
    s = s.replace("\x00", "")
    if len(s) < MIN_STRING_LEN:
        return
    sset.add(s[:MAX_STRING_LEN])


def collect_strings_defined_iterator(program: Any) -> List[str]:
    """
    Use Ghidra's DefinedStringsIterator to collect strings.
    """
    strings_set: Set[str] = set()

    try:
        itr = DefinedStringsIterator(program, True)
    except Exception:
        itr = DefinedStringsIterator(program)

    for item in itr:
        if len(strings_set) >= MAX_STRINGS:
            break
        s_val = None
        try:
            if hasattr(item, "getStringValue"):
                s_val = item.getStringValue()
            elif hasattr(item, "getValue"):
                s_val = item.getValue()
            elif hasattr(item, "toString"):
                s_val = item.toString()
            if s_val is not None:
                _normalize_and_add(strings_set, str(s_val))
        except Exception:
            addr = None
            if hasattr(item, "getAddress"):
                addr = item.getAddress()
            elif hasattr(item, "getMinAddress"):
                addr = item.getMinAddress()
            try:
                inst = StringDataInstance.getStringDataInstance(program, addr)
                if inst is not None:
                    _normalize_and_add(strings_set, str(inst.getStringValue()))
            except Exception:
                pass

    return sorted(strings_set) if strings_set else []


def collect_strings_defined_data(program: Any) -> List[str]:
    """
    Iterate defined data and extract string-like entries.
    """
    strings_set: Set[str] = set()
    listing = program.getListing()

    for d in listing.getDefinedData(True):
        if len(strings_set) >= MAX_STRINGS:
            break
        try:
            dt = d.getDataType()
            dt_name = str(getattr(dt, "getDisplayName", lambda: str(dt))()).lower()
            if "string" in dt_name or "unicode" in dt_name or "utf" in dt_name:
                s_val = None
                try:
                    if hasattr(d, "getDefaultValueRepresentation"):
                        s_val = d.getDefaultValueRepresentation()
                    elif hasattr(d, "getValue"):
                        s_val = d.getValue()
                except Exception:
                    s_val = None
                try:
                    inst = StringDataInstance.getStringDataInstance(program, d.getAddress())
                    if inst is not None:
                        s_val = inst.getStringValue()
                except Exception:
                    pass
                if s_val is not None:
                    _normalize_and_add(strings_set, str(s_val))
        except Exception:
            pass
    return sorted(strings_set) if strings_set else []


def collect_strings_bytescan(program: Any) -> List[str]:
    """
    Byte-scan head/tail of initialized memory blocks for ASCII and UTF-16LE strings.
    """

    def _extract_ascii(data: bytes) -> List[str]:
        out: List[str] = []
        run: bytearray = bytearray()
        for b in data:
            if 32 <= b <= 126:
                run.append(b)
                if len(run) >= MAX_STRING_LEN:
                    out.append(run.decode("ascii", errors="ignore"))
                    run.clear()
            else:
                if len(run) >= MIN_STRING_LEN:
                    out.append(run.decode("ascii", errors="ignore"))
                run.clear()
            if len(out) >= MAX_STRINGS:
                break
        if len(run) >= MIN_STRING_LEN and len(out) < MAX_STRINGS:
            out.append(run.decode("ascii", errors="ignore"))
        return out

    def _extract_utf16le(data: bytes) -> List[str]:
        out: List[str] = []
        for start in (0, 1):
            run_len = 0
            i = start
            limit = len(data) - 1
            while i < limit:
                low = data[i]
                high = data[i + 1]
                if 32 <= low <= 126 and high == 0:
                    run_len += 1
                else:
                    if run_len >= MIN_STRING_LEN:
                        begin = i - (run_len * 2)
                        end = i
                        s = data[begin:end][: MAX_STRING_LEN * 2].decode(
                            "utf-16le", errors="ignore"
                        )
                        if s:
                            out.append(s)
                        if len(out) >= MAX_STRINGS:
                            return out
                    run_len = 0
                i += 2
            if run_len >= MIN_STRING_LEN and len(out) < MAX_STRINGS:
                begin = i - (run_len * 2)
                end = i
                s = data[begin:end][: MAX_STRING_LEN * 2].decode("utf-16le", errors="ignore")
                if s:
                    out.append(s)
        return out

    strings_set: Set[str] = set()
    try:
        memory: Any = program.getMemory()
        for block in memory.getBlocks():
            try:
                if not getattr(block, "isInitialized", lambda: True)():
                    continue
                total = int(block.getSize())
                head_len = min(total, MAX_BLOCK_SCAN_BYTES)
                head_bytes = bytearray(head_len)
                try:
                    read = memory.getBytes(block.getStart(), head_bytes) or 0
                    if read < head_len:
                        head_bytes = head_bytes[: max(0, read)]
                except Exception:
                    head_bytes = bytearray()

                tail_bytes: bytearray | bytes = bytearray()
                if total > head_len:
                    tail_len = min(MAX_BLOCK_SCAN_BYTES, total - head_len)
                    tail_bytes = bytearray(tail_len)
                    try:
                        tail_start_addr = block.getEnd().subtract(tail_len - 1)
                        read_tail = memory.getBytes(tail_start_addr, tail_bytes) or 0
                        if read_tail < tail_len:
                            tail_bytes = tail_bytes[: max(0, read_tail)]
                    except Exception:
                        tail_bytes = bytearray()

                for segment in (bytes(head_bytes), bytes(tail_bytes)):
                    if not segment:
                        continue
                    if len(strings_set) < MAX_STRINGS:
                        for s in _extract_ascii(segment):
                            _normalize_and_add(strings_set, s)
                            if len(strings_set) >= MAX_STRINGS:
                                break
                    if len(strings_set) < MAX_STRINGS:
                        for s in _extract_utf16le(segment):
                            _normalize_and_add(strings_set, s)
                            if len(strings_set) >= MAX_STRINGS:
                                break
                if len(strings_set) >= MAX_STRINGS:
                    break
            except Exception:
                pass
    except Exception as e:
        LOGGER.error("Failed to iterate memory for strings: %s", e)

    return sorted(strings_set) if strings_set else []
