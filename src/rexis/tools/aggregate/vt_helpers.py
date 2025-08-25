from typing import Any, Dict, List, Optional, Tuple

from rexis.tools.aggregate.text_utils import (
    infer_category_from_many_texts,
    infer_category_from_text,
)
from rexis.utils.constants import CATEGORIES
from rexis.utils.utils import safe_get


def collect_vendor_strings(vendor_blob: Any) -> List[str]:
    vendor_strings: List[str] = []
    if isinstance(vendor_blob, dict):
        for entry in vendor_blob.values():
            if isinstance(entry, dict):
                vendor_strings.append(
                    entry.get("result") or entry.get("label") or entry.get("category") or ""
                )
            elif isinstance(entry, str):
                vendor_strings.append(entry)
    elif isinstance(vendor_blob, list):
        for entry in vendor_blob:
            if isinstance(entry, dict):
                vendor_strings.append(
                    entry.get("result") or entry.get("label") or entry.get("category") or ""
                )
            elif isinstance(entry, str):
                vendor_strings.append(entry)
    return [s for s in vendor_strings if s]


def vt_category_candidates(report: Dict[str, Any]) -> List[str]:
    candidate_strings: List[str] = []
    for path in [
        ["virus_total", "data", "vendors"],
        ["virus_total", "vendors"],
        ["decision", "inputs", "virustotal", "vendors"],
        ["virus_total", "data", "results"],
        ["virus_total", "results"],
    ]:
        vendor_blob = safe_get(report, path)
        candidate_strings += collect_vendor_strings(vendor_blob)
    for path in [
        ["virus_total", "data", "popular_threat_name"],
        ["virus_total", "data", "popular_threat_category"],
        ["virus_total", "data", "threat_label"],
        ["virus_total", "data", "threat_category"],
        ["virus_total", "data", "labels"],
    ]:
        value = safe_get(report, path)
        if isinstance(value, list):
            candidate_strings += [str(x) for x in value]
        elif isinstance(value, str):
            candidate_strings.append(value)
    seen: set[str] = set()
    deduped_candidates: List[str] = []
    for s in candidate_strings:
        if s not in seen:
            seen.add(s)
            deduped_candidates.append(s)
    return deduped_candidates


def vt_all_categories(report: Dict[str, Any]) -> List[str]:
    categories: set[str] = set()
    popular_threat_categories = (
        safe_get(report, ["virus_total", "data", "popular_threat_category"], []) or []
    )
    if isinstance(popular_threat_categories, list):
        for entry in popular_threat_categories:
            if isinstance(entry, dict):
                value = str(entry.get("value", "")).lower().strip()
                if value in CATEGORIES:
                    categories.add(value)
            elif isinstance(entry, str):
                value = entry.lower().strip()
                if value in CATEGORIES:
                    categories.add(value)
    for candidate in vt_category_candidates(report):
        inferred = infer_category_from_text(candidate)
        if inferred and inferred in CATEGORIES:
            categories.add(inferred)
    return sorted(categories)


def vt_truth_category(report: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    info: Dict[str, Any] = {}
    popular_categories = (
        safe_get(report, ["virus_total", "data", "popular_threat_category"], []) or []
    )
    if isinstance(popular_categories, list) and popular_categories:
        best = max(
            (c for c in popular_categories if isinstance(c, dict) and "value" in c),
            key=lambda c: c.get("count", 0),
            default=None,
        )
        if best:
            value = str(best.get("value", "")).lower()
            if value in CATEGORIES:
                info["method"] = "vt_popular_threat_category"
                info["vendor_str_count"] = 0
                return value, info
    vendor_texts = vt_category_candidates(report)
    voted_category = infer_category_from_many_texts(vendor_texts)
    if voted_category:
        info["method"] = "vendor_vote"
        info["vendor_str_count"] = len(vendor_texts)
        return voted_category, info

    vt_malicious = safe_get(report, ["virus_total", "data", "malicious"])
    vt_total = safe_get(report, ["virus_total", "data", "total"]) or safe_get(
        report, ["virus_total", "data", "scanned"]
    )
    consensus_ratio = (
        (vt_malicious / vt_total)
        if isinstance(vt_malicious, int) and isinstance(vt_total, int) and vt_total > 0
        else None
    )
    if consensus_ratio is not None and consensus_ratio >= 0.6:
        label = (
            safe_get(report, ["decision", "final", "label"])
            or safe_get(report, ["final", "label"])
            or ""
        )
        cat = infer_category_from_text(label)
        if cat:
            info["method"] = "fallback_label"
            info["vendor_str_count"] = len(vendor_texts)
            return cat, info
    info["method"] = "none"
    info["vendor_str_count"] = len(vendor_texts)
    return None, info
