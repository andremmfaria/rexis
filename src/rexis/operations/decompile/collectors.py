from typing import Any, List, Set

from rexis.operations.decompile.utils import (
    calc_entropy,
    count_ascii_strings,
    count_utf16le_strings,
    read_bytes_slow,
)
from rexis.utils.types import FunctionInfo, MemorySection
from rexis.utils.utils import LOGGER

# Public constants
MAX_SECTION_SAMPLE_BYTES = 1 << 20
DEFAULT_MIN_STRING_LEN = 4
DEFAULT_INCLUDE_WIDE = True
DEFAULT_REQUIRE_NUL = False
DEFAULT_ALIGNMENT = 1


def collect_functions(program: Any) -> List[FunctionInfo]:
    program_listing: Any = program.getListing()
    functions: List[FunctionInfo] = []
    for ghidra_function in program_listing.getFunctions(True):
        try:
            functions.append(
                {
                    "name": ghidra_function.getName(),
                    "entry": str(ghidra_function.getEntryPoint()),
                    "size": ghidra_function.getBody().getNumAddresses(),
                    "is_thunk": bool(getattr(ghidra_function, "isThunk", lambda: False)()),
                    "calling_convention": (
                        ghidra_function.getCallingConventionName()
                        if hasattr(ghidra_function, "getCallingConventionName")
                        else None
                    ),
                }
            )
        except Exception as err:
            LOGGER.error(
                "Skipping function %s due to error: %s",
                ghidra_function.getName(),
                err,
            )
    return functions


def collect_imports(program: Any) -> List[str]:
    """
    Collect names of external symbols as a proxy for imported APIs.
    Some Ghidra versions/types may not tag imports strictly as FUNCTION; be permissive.
    """
    external_symbol_names: Set[str] = set()
    try:
        symbol_table: Any = program.getSymbolTable()
        for symbol in symbol_table.getExternalSymbols():
            try:
                name = symbol.getName()
                if name:
                    external_symbol_names.add(str(name))
            except Exception:
                pass
    except Exception as err:
        LOGGER.error("Failed collecting external symbols: %s", err)
    return sorted(external_symbol_names)


def collect_sections(program: Any) -> List[MemorySection]:
    memory_sections: List[MemorySection] = []
    program_memory = program.getMemory()
    function_manager = program.getFunctionManager()
    function_entry_points = [
        function.getEntryPoint() for function in function_manager.getFunctions(True)
    ]

    # include overlays
    try:
        memory_blocks = list(program_memory.getBlocks(True))
    except Exception:
        memory_blocks = list(program_memory.getBlocks())

    for memory_block in memory_blocks:
        try:
            section_info = {
                "name": memory_block.getName(),
                "start": str(memory_block.getStart()),
                "end": str(memory_block.getEnd()),
                "size": int(memory_block.getSize()),
                "initialized": bool(memory_block.isInitialized()),
                "read": bool(memory_block.isRead()),
                "write": bool(memory_block.isWrite()),
                "execute": bool(memory_block.isExecute()),
                "volatile": bool(memory_block.isVolatile()),
                "overlay": bool(memory_block.isOverlay()),
                "loaded": bool(memory_block.isLoaded()),
                "type": str(memory_block.getType()) if hasattr(memory_block, "getType") else None,
                "source_name": (
                    memory_block.getSourceName() if hasattr(memory_block, "getSourceName") else None
                ),
                "comment": (
                    memory_block.getComment() if hasattr(memory_block, "getComment") else None
                ),
            }

            block_total_size = int(memory_block.getSize())
            sample_byte_count = min(block_total_size, MAX_SECTION_SAMPLE_BYTES)
            is_bytes_truncated = block_total_size > sample_byte_count

            sampled_bytes = b""
            bytes_read = 0
            if sample_byte_count > 0 and memory_block.isInitialized():
                try:
                    sampled_bytes = read_bytes_slow(
                        program_memory, memory_block.getStart(), sample_byte_count
                    )
                    bytes_read = len(sampled_bytes)
                except Exception as read_error:
                    LOGGER.error(f"Failed reading {section_info['name']}: {read_error}")
                    sampled_bytes = b""
                    bytes_read = 0
            else:
                if sample_byte_count == 0:
                    LOGGER.warning(f"Section {section_info['name']} has zero size; skipping sample.")
                elif not memory_block.isInitialized():
                    LOGGER.warning(f"Section {section_info['name']} is uninitialized; skipping sample.")

            # --- Entropy / strings / funcs
            section_info["entropy"] = calc_entropy(sampled_bytes)
            section_info["strings_count"] = count_ascii_strings(
                sampled_bytes
            ) + count_utf16le_strings(sampled_bytes)
            section_info["functions_count"] = sum(
                1 for entry_addr in function_entry_points if memory_block.contains(entry_addr)
            )
            section_info["bytes_total"] = block_total_size
            section_info["bytes_sampled"] = bytes_read
            section_info["bytes_truncated"] = is_bytes_truncated
            memory_sections.append(section_info)

            # --- DEBUG PREVIEW: first 64 bytes + quick stats
            if sampled_bytes:
                preview = sampled_bytes[: min(64, len(sampled_bytes))]
                hex_preview = " ".join(f"{b:02x}" for b in preview)
                # quick freq count
                freq = {}
                for b in preview:
                    freq[b] = freq.get(b, 0) + 1
                unique_bytes = len(freq)
                if freq:
                    most_byte, most_count = max(freq.items(), key=lambda kv: kv[1])
                    most_byte_str = f"0x{most_byte:02x}×{most_count}"
                else:
                    most_byte_str = "n/a"

                LOGGER.info(
                    f"Section {section_info['name']} | sampled={len(sampled_bytes)}/{block_total_size} | "
                    f"init={section_info['initialized']} | entropy={section_info['entropy']:.4f} | "
                    f"unique={unique_bytes} | most={most_byte_str} | hexdump[0:64]={hex_preview}"
                )
            else:
                LOGGER.info(
                    f"Section {section_info['name']} | sampled=0/{block_total_size} | "
                    f"init={section_info['initialized']} | entropy=0.0000 (no data)"
                )

        except Exception as block_error:
            LOGGER.error(
                f"Error collecting section {getattr(memory_block, 'getName', lambda: '<unknown>')()}: {block_error}"
            )

    memory_sections.sort(key=lambda s: s.get("start", ""))
    return memory_sections


def collect_libraries(program: Any) -> List[str]:
    libraries: List[str] = []
    try:
        external_manager = program.getExternalManager()
        try:
            for library_name in external_manager.getExternalLibraryNames():
                try:
                    libraries.append(str(library_name))
                except Exception:
                    pass
        except Exception:
            pass
        if not libraries:
            try:
                symbol_table = program.getSymbolTable()
                library_namespace_names_set = set()
                for symbol in symbol_table.getExternalSymbols():
                    try:
                        parent_namespace = symbol.getParentNamespace()
                        if parent_namespace is not None:
                            library_namespace_names_set.add(str(parent_namespace.getName()))
                    except Exception:
                        pass
                libraries = sorted(library_namespace_names_set)
            except Exception:
                libraries = []
    except Exception:
        libraries = []
    return libraries


def collect_exports(program: Any) -> List[str]:
    exports: List[str] = []
    try:
        symbol_table = program.getSymbolTable()
        for symbol in symbol_table.getAllSymbols(True):
            try:
                if getattr(symbol, "isExternal", lambda: False)():
                    continue
                if getattr(symbol, "isGlobal", lambda: False)():
                    exports.append(symbol.getName())
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
        program_entry_point = program.getProgramEntryPoint()
        if program_entry_point is not None:
            entry_points.append(str(program_entry_point))
    except Exception:
        pass
    try:
        function_manager = program.getFunctionManager()
        for function in function_manager.getFunctions(True):
            try:
                if hasattr(function, "isEntryPoint") and function.isEntryPoint():
                    entry_points.append(str(function.getEntryPoint()))
            except Exception:
                pass
    except Exception:
        pass
    try:
        entry_points = sorted(set(entry_points))
    except Exception:
        pass
    return entry_points


def collect_strings(program_pointer: Any, program_instance: Any) -> List[str]:
    """
    Returns a list of strings using Ghidra's built-in string finder.
    - min_len: minimum characters to consider a string
    - include_wide: include UTF-16/UTF-32 if True
    - require_nul: require null-terminated strings only
    - alignment: 1 (any), 2 (even), or 4
    """
    program_memory = program_instance.getMemory()

    try:
        found_strings = program_pointer.findStrings(
            None,
            int(DEFAULT_MIN_STRING_LEN),
            int(DEFAULT_ALIGNMENT),
            bool(DEFAULT_REQUIRE_NUL),
            bool(DEFAULT_INCLUDE_WIDE),
        )
    except Exception as err:
        LOGGER.error("findStrings failed: %s", err)
        found_strings = []

    strings: List[str] = []
    for found_string in found_strings:
        try:
            text = found_string.getString(program_memory)
            if text is None:
                continue
            strings.append(text)
        except Exception:
            pass

    return strings
