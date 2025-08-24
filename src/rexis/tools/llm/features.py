import re
from typing import Any, Dict, List, Optional

from rexis.utils.constants import (
    CAPABILITY_BUCKETS,
    EXPORTS_CAP,
    PACKER_MARKERS,
    RESOURCE_CAP,
    STRING_CAP_PER_CATEGORY,
    STRING_CATEGORY_PATTERNS,
)
from rexis.utils.types import (
    ExportsInfo,
    Features,
    ImportsByCapability,
    PackerHints,
    ProgramInfo,
    ResourceInfo,
    ResourcesInfo,
    SummarizedFeatures,
)


def _limit_list(values: Optional[List[Any]], cap: int) -> List[Any]:
    values = values or []
    return values[:cap]


def _extract_exports(features: Features) -> Optional[ExportsInfo]:
    exports = features.get("exports") or []
    if not exports and not (
        features.get("entry_point") or (features.get("program") or {}).get("entry_point")
    ):
        return None

    names: List[str] = []
    for item in exports:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("symbol")
            if name:
                names.append(str(name))

    entry_point = features.get("entry_point") or (features.get("program") or {}).get("entry_point")
    tls_callbacks = features.get("tls_callbacks") or []
    result: ExportsInfo = {
        "names": _limit_list(sorted(list(dict.fromkeys(names))), EXPORTS_CAP) or None,
        "entry_point": entry_point,
        "tls_callbacks": _limit_list(tls_callbacks, 10) or None,
    }
    # Remove keys that ended up as None to keep payload compact
    return {k: v for k, v in result.items() if v is not None} or None


def _categorize_strings(strings: List[str]) -> Optional[Dict[str, List[str]]]:
    if not strings:
        return None

    # Build compiled regexes from constants
    compiled: Dict[str, List[re.Pattern]] = {}
    for cat, patterns in STRING_CATEGORY_PATTERNS.items():
        compiled[cat] = [re.compile(p, re.I) for p in patterns]

    cats: Dict[str, List[str]] = {cat: [] for cat in STRING_CATEGORY_PATTERNS.keys()}

    for s in strings:
        if not isinstance(s, str):
            continue
        for cat, regex_list in compiled.items():
            for regex in regex_list:
                # For URL/IP/Email we can extend with all matches; for others take first match for brevity
                matches = regex.findall(s)
                if not matches:
                    continue
                if cat in {"urls", "ips", "emails"}:
                    if isinstance(matches, list):
                        cats[cat].extend(
                            matches if isinstance(matches[0], str) else [m[0] for m in matches]
                        )
                else:
                    # Use search-like behavior: just the first match
                    first = matches[0]
                    cats[cat].append(first if isinstance(first, str) else first[0])

    # Dedup and cap
    out: Dict[str, List[str]] = {}
    for key, items in cats.items():
        if items:
            deduped = list(dict.fromkeys(items))
            out[key] = deduped[:STRING_CAP_PER_CATEGORY]

    return out or None


def _extract_strings(features: Features) -> Optional[Dict[str, List[str]]]:
    raw_strings = features.get("strings") or []
    return _categorize_strings(raw_strings)


def _extract_resources(features: Features) -> Optional[ResourcesInfo]:
    resources = features.get("resources") or []
    if not resources:
        return None
    out: ResourcesInfo = []
    for r in resources[:RESOURCE_CAP]:
        if not isinstance(r, dict):
            continue
        size = r.get("size")
        entropy = r.get("entropy")
        tags: List[str] = []
        try:
            if isinstance(entropy, (int, float)) and entropy >= 7.0:
                tags.append("high-entropy")
            if isinstance(size, int) and size and size > 1024 * 1024:
                tags.append("large")
        except Exception:
            pass
        res: ResourceInfo = {
            "type": r.get("type") or r.get("name"),
            "size": size,
            "entropy": entropy,
            "tags": tags or None,
        }
        out.append(res)
    return out or None


def _extract_imports_by_capability(features: Features) -> ImportsByCapability:
    import_names: List[str] = [
        name for name in (features.get("imports") or []) if isinstance(name, str)
    ]
    import_names_lower: List[str] = [name.lower() for name in import_names]

    imports_by_capability_map: ImportsByCapability = {}
    for capability, tokens in CAPABILITY_BUCKETS.items():
        matched_imports: List[str] = sorted(
            {imp for imp in import_names_lower if any(token in imp for token in tokens)}
        )
        if matched_imports:
            imports_by_capability_map[capability] = matched_imports[:10]
    return imports_by_capability_map


def _extract_packer_hints(features: Features) -> PackerHints:
    # Packer hints (strings/sections-dependent; keep generic)
    import_names: List[str] = [
        name for name in (features.get("imports") or []) if isinstance(name, str)
    ]
    import_names_lower: List[str] = [name.lower() for name in import_names]

    hints: List[str] = []
    if any(marker in " ".join(import_names_lower) for marker in PACKER_MARKERS):
        hints.append("packer-string")

    # Tiny .text if sections are present and RWX flags
    for section in features.get("sections", []) or []:
        section_name: str = str(section.get("name", "")).lower()
        section_size: int = int(section.get("size", 0) or 0)
        section_flags: List[str] = [str(flag).lower() for flag in section.get("flags", []) or []]
        if section_name in {".text", "text"} and 0 < section_size < 4096:
            hints.append("tiny-.text")
        if "exec" in section_flags and "write" in section_flags:
            hints.append("writable+exec section")
    return hints


def summarize_features(features: Features) -> SummarizedFeatures:
    program_metadata: ProgramInfo = features.get("program") or {}
    packer_hints: PackerHints = _extract_packer_hints(features)
    exports_info: ExportsInfo = _extract_exports(features) or {}
    strings_info: Dict[str, List[str]] = _extract_strings(features) or {}
    resources_info: ResourcesInfo = _extract_resources(features) or []
    imports_by_capability_map: ImportsByCapability = _extract_imports_by_capability(features)

    sections_summary: List[Dict[str, Any]] = []
    for section in features.get("sections") or []:
        sections_summary.append(
            {
                "name": section.get("name"),
                "size": section.get("size"),
                "flags": section.get("flags"),
                "entropy": section.get("entropy"),
                "comment": section.get("comment"),
                "type": section.get("type"),
                "read": section.get("read"),
                "write": section.get("write"),
            }
        )

    result: SummarizedFeatures = {
        "program": program_metadata,
        "imports_by_capability": imports_by_capability_map,
        "packer_hints": packer_hints or None,
        "sections": sections_summary or None,
        "exports": exports_info,
        "strings": strings_info,
        "resources": resources_info,
    }

    return result
