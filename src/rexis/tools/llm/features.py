from typing import Any, Dict, List

from rexis.utils.constants import CAPABILITY_BUCKETS


def summarize_features(features: Dict[str, Any]) -> Dict[str, Any]:
    prog: Dict[str, Any] = features.get("program") or {}
    imports: List[str] = [i for i in (features.get("imports") or []) if isinstance(i, str)]
    imports_lc: List[str] = [i.lower() for i in imports]

    imports_by_cap: Dict[str, List[str]] = {}
    for cap, toks in CAPABILITY_BUCKETS.items():
        hits: List[str] = sorted({i for i in imports_lc if any(tok in i for tok in toks)})
        if hits:
            imports_by_cap[cap] = hits[:10]

    # Packer hints (strings/sections-dependent; keep generic)
    packer_hints: List[str] = []
    if any(x in " ".join(imports_lc) for x in ["upx", "mpress", "aspack", "themida"]):
        packer_hints.append("packer-string")
    # Tiny .text if sections are present
    for s in features.get("sections", []) or []:
        name: str = str(s.get("name", "")).lower()
        sz: int = int(s.get("size", 0) or 0)
        flags: List[str] = [str(f).lower() for f in s.get("flags", []) or []]
        if name in {".text", "text"} and 0 < sz < 4096:
            packer_hints.append("tiny-.text")
        if "exec" in flags and "write" in flags:
            packer_hints.append("writable+exec section")

    # Compact sections block (optional, if present)
    sections_summary: List[Dict[str, Any]] = []
    for s in (features.get("sections") or [])[:5]:
        sections_summary.append(
            {"name": s.get("name"), "size": s.get("size"), "flags": s.get("flags")}
        )

    return {
        "program": {
            "name": prog.get("name"),
            "format": prog.get("format"),
            "compiler": prog.get("compiler"),
            "language": prog.get("language"),
            "image_base": prog.get("image_base"),
            "size": prog.get("size"),
            "sha256": prog.get("sha256"),
        },
        "imports_by_capability": imports_by_cap,
        "packer_hints": packer_hints or None,
        "sections": sections_summary or None,
    }
