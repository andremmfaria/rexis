from typing import Any, Dict, List, Tuple


def build_queries_from_features(features: Dict[str, Any], max_terms: int = 12) -> List[str]:
    imps = [i.lower() for i in (features.get("imports") or []) if isinstance(i, str)]
    imps_top = sorted(set(imps))[:max_terms]

    prog = features.get("program") or {}
    fmt = prog.get("format")
    comp = prog.get("compiler")
    lang = prog.get("language")

    seeds: List[str] = []
    if imps_top:
        seeds.append("imports: " + ", ".join(imps_top))
    if fmt:
        seeds.append(f"format: {fmt}")
    if comp:
        seeds.append(f"compiler: {comp}")
    if lang:
        seeds.append(f"language: {lang}")
    return seeds[:max_terms]


def retrieve_context(
    queries: List[str],
    top_k: int = 8,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Placeholder for Haystack retrieval. Returns (passages, notes).
    Each passage: {"doc_id","source","title","score","text"}.
    """
    notes = []
    if not queries:
        notes.append("No queries built from features")
        return [], notes
    # Stub: return empty result set but record what would've been searched.
    notes.append(f"RAG stub invoked with {len(queries)} queries; top_k={top_k}")
    return [], notes
