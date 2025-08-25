from typing import Any, Dict, Set

from rexis.tools.aggregate.text_utils import infer_category_from_text
from rexis.utils.constants import CATEGORIES
from rexis.utils.utils import safe_get


def parse_baseline(report: Dict[str, Any]) -> Dict[str, Any]:
    label = (
        safe_get(report, ["decision", "final", "label"])
        or safe_get(report, ["final", "label"])
        or "unknown"
    )
    sha256 = (
        safe_get(report, ["sample", "sha256"]) or safe_get(report, ["program", "sha256"]) or None
    )
    duration_sec = safe_get(report, ["duration_sec"], 0.0)

    pred_categories: Set[str] = set()
    h_class = safe_get(report, ["heuristics", "classification"])
    if isinstance(h_class, list):
        for x in h_class:
            t = str(x).strip().lower()
            if t in CATEGORIES:
                pred_categories.add(t)

    ev_list = safe_get(report, ["heuristics", "evidence"], []) or []
    rules_triggered = len(ev_list) if isinstance(ev_list, list) else 0
    rules_consistent = 0
    if isinstance(ev_list, list) and pred_categories:
        pred_set = set(pred_categories)
        for evidence in ev_list:
            categories = evidence.get("categories") or []
            cat_tags = {str((c or {}).get("tag", "")).strip().lower() for c in categories}
            if pred_set.intersection(cat_tags):
                rules_consistent += 1

    return {
        "sha256": sha256,
        "label": label,
        "pred_categories": sorted(pred_categories) if pred_categories else [],
        "duration_sec": float(duration_sec) if duration_sec is not None else None,
        "explanation_present": bool(ev_list),
        "rules_triggered": rules_triggered,
        "rules_consistent": rules_consistent,
    }


def parse_llmrag(report: Dict[str, Any]) -> Dict[str, Any]:
    label = safe_get(report, ["llmrag", "label"]) or "unknown"
    sha256 = (
        safe_get(report, ["sample", "sha256"]) or safe_get(report, ["program", "sha256"]) or None
    )
    duration_sec = safe_get(report, ["duration_sec"], 0.0)
    evidence = safe_get(report, ["llmrag", "evidence"], []) or []
    passages_used = (
        safe_get(report, ["llmrag", "meta", "passages_used"], [])
        or safe_get(report, ["artifacts", "retrieval", "passages_used"], [])
        or []
    )

    classification_list = safe_get(report, ["llmrag", "classification"], []) or []
    pred_categories: Set[str] = set()
    if isinstance(classification_list, list):
        for x in classification_list:
            t = str(x).strip().lower()
            if t in CATEGORIES:
                pred_categories.add(t)
    label_inferred = infer_category_from_text(label)
    if label_inferred and label_inferred in CATEGORIES:
        pred_categories.add(label_inferred)

    return {
        "sha256": sha256,
        "label": label,
        "pred_categories": sorted(pred_categories) if pred_categories else [],
        "duration_sec": float(duration_sec) if duration_sec is not None else None,
        "explanation_present": bool(evidence),
        "grounding_ge1": len(set(passages_used)) >= 1,
        "grounding_ge2": len(set(passages_used)) >= 2,
    }
