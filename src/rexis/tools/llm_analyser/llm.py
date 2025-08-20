from typing import Any, Dict, List


def llm_classify_stub(
    features: Dict[str, Any],
    passages: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Stand-in for the real LLM JSON output. Produces a minimal, comparable structure.
    """
    # Cheap signal: if clear injection APIs exist, mark as suspicious with a modest score.
    imps = {i.lower() for i in (features.get("imports") or []) if isinstance(i, str)}
    inj = {"createremotethread", "writeprocessmemory", "virtualallocex", "ntunmapviewofsection"}

    if imps & inj:
        score = 0.55
        label = "suspicious"
        evidence = [
            {
                "id": "cap_injection",
                "title": "Possible process injection capability",
                "detail": f"Imports include: {', '.join(sorted(imps & inj))}",
                "severity": "warn",
                "source": "features",
                "doc_ref": "imports",
            }
        ]
        uncertainty = "medium"
    else:
        score = 0.20
        label = "benign"
        evidence = [
            {
                "id": "insufficient_signal",
                "title": "Low confidence assessment",
                "detail": "No strong capability indicators in imports",
                "severity": "info",
                "source": "features",
                "doc_ref": "imports",
            }
        ]
        uncertainty = "high"

    return {
        "score": round(score, 4),
        "label": label,
        "families": [],
        "capabilities": ["injection"] if label != "benign" else [],
        "tactics": [],
        "evidence": evidence,
        "uncertainty": uncertainty,
    }
