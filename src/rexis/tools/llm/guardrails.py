import re
from typing import Any, Dict, List, Tuple, Set, Optional

from rexis.tools.llm.main import llm_classify
from rexis.utils.utils import LOGGER
from rexis.utils.constants import REDACT_TOKEN, DEFAULT_FAMILY_TERMS, TECH_TOKENS


def extract_family_or_actor_names(input_text: str) -> Set[str]:
    """Extract likely malware family or threat actor names (capitalized words/compounds) from input text."""
    # Examples: Emotet, QakBot, "APT28", "Cobalt Strike", "RedLine"
    name_pattern = re.compile(r"\b(?:APT\d{1,3}|[A-Z][A-Za-z0-9]+(?:[-\s][A-Z][A-Za-z0-9]+){0,2})\b")
    matches = set(match.group(0) for match in name_pattern.finditer(input_text or ""))
    LOGGER.info(f"Extracted family/actor names: {matches}")
    return matches


def build_family_actor_name_set(document_passages: List[Dict[str, Any]], additional_names: Optional[Set[str]] = None) -> Set[str]:
    """Build a set of malware family and actor names from passages and additional names."""
    family_actor_names: Set[str] = set(DEFAULT_FAMILY_TERMS)
    LOGGER.info(f"Starting family/actor name set with DEFAULT_FAMILY_TERMS: {DEFAULT_FAMILY_TERMS}")
    for passage in document_passages:
        family_actor_names |= extract_family_or_actor_names(str(passage.get("title") or ""))
        family_actor_names |= extract_family_or_actor_names(str(passage.get("text") or ""))
    if additional_names:
        family_actor_names |= {extra_name for extra_name in additional_names if extra_name and isinstance(extra_name, str)}
        LOGGER.info(f"Added extra names: {additional_names}")
    result_set = set(name.strip() for name in family_actor_names if name.strip())
    LOGGER.info(f"Final family/actor name set: {result_set}")
    return result_set


def redact_names_in_text(input_text: str, names_to_redact: Set[str]) -> Tuple[str, Dict[str, int]]:
    """Replace any case-insensitive family/actor name hits in text with REDACT_TOKEN; return map of redaction counts."""
    redaction_counts: Dict[str, int] = {}
    redacted_text = input_text or ""
    LOGGER.info(f"Redacting names in text. Names to redact: {names_to_redact}")
    for name in sorted(names_to_redact, key=lambda s: len(s), reverse=True):
        if not name:
            continue
        name_regex = re.compile(rf"(?<![#\w]){re.escape(name)}(?![#\w])", re.IGNORECASE)
        redacted_text, num_replacements = name_regex.subn(REDACT_TOKEN, redacted_text)
        if num_replacements:
            redaction_counts[name] = redaction_counts.get(name, 0) + num_replacements
            LOGGER.info(f"Redacted '{name}' {num_replacements} times.")
    LOGGER.info(f"Redaction counts: {redaction_counts}")
    return redacted_text, redaction_counts


def redact_passages(
    passages: List[Dict[str, Any]], extra_names: Optional[Set[str]] = None
) -> Tuple[List[Dict[str, Any]], Set[str], Dict[str, int]]:
    """Return sanitized passages, the name-set used, and aggregate redaction counts."""
    print(f"[guardrails] Redacting passages...")
    name_set = build_family_actor_name_set(passages, additional_names=extra_names)
    aggregate_redaction_counts: Dict[str, int] = {}
    sanitized_passages: List[Dict[str, Any]] = []
    for passage in passages:
        passage_text = str(passage.get("text") or "")
        redacted_text, passage_redaction_counts = redact_names_in_text(passage_text, name_set)
        for name, count in passage_redaction_counts.items():
            aggregate_redaction_counts[name] = aggregate_redaction_counts.get(name, 0) + count
        sanitized_passage = dict(passage)
        sanitized_passage["text"] = redacted_text
        sanitized_passages.append(sanitized_passage)
    LOGGER.info(f"Sanitized passages: {len(sanitized_passages)}. Aggregate redaction counts: {aggregate_redaction_counts}")
    return sanitized_passages, name_set, aggregate_redaction_counts


def count_technical_term_matches(passage_text: str) -> int:
    """Count how many technical tokens are present in the passage text."""
    normalized_text = (passage_text or "").lower()
    return sum(1 for technical_token in TECH_TOKENS if technical_token.lower() in normalized_text)


def count_family_actor_name_mentions(passage_text: str, family_actor_names: Set[str]) -> int:
    """Count how many family/actor names are mentioned in the passage text."""
    normalized_text = (passage_text or "").lower()
    return sum(1 for name in family_actor_names if name.lower() in normalized_text)


def rerank_passages_by_technicality(
    passages: List[Dict[str, Any]], family_actor_names: Set[str], top_k: int = 8
) -> List[Dict[str, Any]]:
    """Score passages by boosting technical signal and penalizing family/actor name mentions, then keep top_k."""
    print(f"[guardrails] Reranking passages by technicality...")
    scored_passages = []
    for passage in passages:
        passage_text = str(passage.get("text") or "")
        tech_count = count_technical_term_matches(passage_text)
        fam_count = count_family_actor_name_mentions(passage_text, family_actor_names)
        score = 5 * tech_count - 3 * fam_count
        score += float(passage.get("score") or 0.0)
        scored_passages.append((score, passage))
        LOGGER.info(f"Passage {passage.get('doc_id', '')}: tech_terms={tech_count}, fam_mentions={fam_count}, score={score}")
    scored_passages.sort(key=lambda x: x[0], reverse=True)
    top_passages = [passage for _, passage in scored_passages[:top_k]]
    LOGGER.info(f"Top {top_k} passages selected after reranking.")
    return top_passages


def collect_retrieval_evidence_items(result_object: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return only evidence items with source 'retrieval' from the result object."""
    evidence_items = result_object.get("evidence") or []
    return [evidence for evidence in evidence_items if str(evidence.get("source")).lower() == "retrieval"]


def extract_family_names(result_object: Dict[str, Any]) -> List[str]:
    """Extract and clean family names from the result object."""
    family_names = result_object.get("families") or []
    return [str(family_name).strip() for family_name in family_names if str(family_name).strip()]


def is_name_leak_detected(candidate_name: str, redacted_names: Set[str]) -> bool:
    """Return True if candidate_name matches a redacted term (case-insensitive)."""
    normalized_candidate = candidate_name.lower()
    return any(normalized_candidate == redacted_name.lower() for redacted_name in redacted_names)


def post_validate(
    justified: Dict[str, Any],
    blind: Dict[str, Any],
    names: Set[str],
    min_retrieval_evidence: int = 2,
) -> Dict[str, Any]:
    """Apply post-hoc checks: evidence requirement, name-leak block, uncertainty bump."""
    out = dict(justified)
    fams = extract_family_names(out)
    retrieval_evidence = collect_retrieval_evidence_items(out)
    insufficient = len(retrieval_evidence) < min_retrieval_evidence

    print(f"[guardrails] Post-validating classification output...")
    LOGGER.info(f"Post-validating: families={fams}, retrieval_evidence_count={len(retrieval_evidence)}, min_required={min_retrieval_evidence}")

    leak = any(is_name_leak_detected(f, names) for f in fams)
    if fams and (leak or insufficient):
        out["families"] = ["unknown_family"]
        out["uncertainty"] = "high"
        notes = str(out.get("notes") or "")
        extra = " guardrails:family_abstained(leak=%s, ev=%d)" % (
            str(leak).lower(),
            len(retrieval_evidence),
        )
        out["notes"] = (notes + extra) if notes else extra
        LOGGER.info(f"Family claim neutralized due to leak={leak} or insufficient evidence.")

    out["guardrails"] = {
        "blind_label": blind.get("label"),
        "blind_families": extract_family_names(blind),
        "blind_score": blind.get("score"),
        "retrieval_evidence_count": len(retrieval_evidence),
        "min_retrieval_evidence": min_retrieval_evidence,
        "name_leak_detected": bool(leak),
    }
    LOGGER.info(f"Guardrails meta attached: {out['guardrails']}")
    return out


def two_stage_classify(
    features: Dict[str, Any],
    passages: List[Dict[str, Any]],
    model: str,
    temperature: float,
    max_tokens: int,
    classify_fn=llm_classify,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]], Set[str], Dict[str, int]]:
    """
    Stage A: classify with NO RAG (blind hypothesis).
    Stage B: classify with sanitized + reranked RAG using 'justification' prompt.
    Returns: (blind, justified, passages_used, names, redaction_counts)
    """
    LOGGER.info(f"Starting two-stage classification: model={model}, temperature={temperature}, max_tokens={max_tokens}")
    blind = classify_fn(
        features=features,
        passages=[],
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        prompt_variant="classification",
    )
    LOGGER.info(f"Stage A (blind) classification done.")

    sanitized, names, redaction_counts = redact_passages(passages)
    reranked = rerank_passages_by_technicality(sanitized, names, top_k=8)
    LOGGER.info(f"Stage B (justified) classification with sanitized and reranked passages...")
    justified = classify_fn(
        features=features,
        passages=reranked,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        prompt_variant="justification",
    )
    LOGGER.info(f"Two-stage classification complete.")
    return blind, justified, reranked, names, redaction_counts


def apply_guardrails_and_classify(
    features: Dict[str, Any],
    passages: List[Dict[str, Any]],
    model: str,
    temperature: float,
    max_tokens: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Public entrypoint used by llmrag.py.
    Returns: (final_out, passages_used, guard_meta)
    """
    print(f"[guardrails] Applying guardrails and classifying...")
    blind, justified, used_passages, names, redaction_counts = two_stage_classify(
        features=features,
        passages=passages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    final = post_validate(justified, blind, names, min_retrieval_evidence=2)
    guard_meta = {
        "redacted_names": sorted(list(names)),
        "redaction_counts": {k: int(v) for k, v in redaction_counts.items()},
        "used_passages": [p.get("doc_id") for p in used_passages],
        "strategy": "redact+rereank+two_stage+post_validate",
    }
    print(f"[guardrails] Guardrails applied. Final output ready.")
    return final, used_passages, guard_meta
