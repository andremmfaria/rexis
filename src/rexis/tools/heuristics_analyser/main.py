from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from rexis.tools.heuristics_analyser.rules import (
    rule_anti_vm_strings,
    rule_autorun_persistence,
    rule_crypto_indicators,
    rule_debugger_anti_debug_indicators,
    rule_dynamic_api_resolution,
    rule_entry_in_writable_section,
    rule_filesystem_modification,
    rule_http_exfil_indicators,
    rule_low_entropy_strings,
    rule_networking_indicators,
    rule_packer_artifacts,
    rule_service_persistence,
    rule_shell_execution_indicators,
    rule_suspicious_api_combination,
    rule_suspicious_urls_in_strings,
    rule_tiny_text_section,
)
from rexis.tools.heuristics_analyser.utils import (
    get_nested_value,
    is_rule_enabled,
    load_heuristic_rules,
    severity_is_at_least,
)
from rexis.utils.constants import DEFAULT_TAG_SCORES
from rexis.utils.types import Evidence


def _combine_evidence_score(evidence: List[Evidence], rules: Dict[str, Any]) -> float:
    base: float = float(get_nested_value(rules, "scoring.base", 0.0) or 0.0)
    weights: Dict[str, Any] = rules.get("weights") or {}
    mode: str = (
        get_nested_value(rules, "scoring.combine", "weighted_sum") or "weighted_sum"
    ).lower()

    if mode == "max":
        best: float = 0.0
        for ev in evidence:
            if ev.id in weights:
                best = max(best, min(1.0, ev.score * float(weights.get(ev.id, 1.0))))
        return max(0.0, min(1.0, base if best == 0 else best))

    # default: weighted_sum with cap at 1.0
    total: float = base
    for ev in evidence:
        w: float = float(weights.get(ev.id, 0.0))
        if w <= 0.0:
            continue
        total += min(1.0, ev.score * w)
    return max(0.0, min(1.0, total))


def _label_from_combined_score(score: float, rules: Dict[str, Any], overrides: List[str]) -> str:
    # explicit rule-based overrides first
    label_over: Dict[str, Any] = rules.get("label_overrides") or {}
    for rid in overrides:
        if rid in label_over:
            return str(label_over[rid])

    thr: Dict[str, Any] = get_nested_value(rules, "scoring.label_thresholds", {}) or {}
    if score >= float(thr.get("malicious", 0.7)):
        return "malicious"
    if score >= float(thr.get("suspicious", 0.4)):
        return "suspicious"
    return "benign"


def _compute_tag_scores(evidence: List[Evidence], rules: Dict[str, Any]) -> Dict[str, float]:
    """Compute tag scores from evidence using a configurable mapping.

    Configuration (optional) structure under rules:
    tagging:
        map:
            <rule_id>:
                <tag>: <weight>
        tag_weights:
            <tag>: <global_weight>
        threshold: 0.3
        top_k: 5
    """
    cfg_map: Dict[str, Dict[str, float]] = (
        get_nested_value(rules, "tagging.map", {}) or DEFAULT_TAG_SCORES
    )
    tag_weights: Dict[str, float] = get_nested_value(rules, "tagging.tag_weights", {}) or {}

    scores: Dict[str, float] = {}
    for ev in evidence:
        rule_map: Dict[str, float] = cfg_map.get(ev.id, {})
        if not rule_map:
            continue
        ev_strength: float = max(0.0, min(1.0, float(ev.score)))
        for tag, w in rule_map.items():
            global_w: float = float(tag_weights.get(tag, 1.0))
            contrib: float = ev_strength * float(w) * global_w
            if contrib <= 0:
                continue
            scores[tag] = min(1.0, scores.get(tag, 0.0) + contrib)
    return scores


def heuristic_classify(
    features: Dict[str, Any],
    rules_path: Optional[Path] = None,
    min_severity: str = "info",
) -> Dict[str, Any]:
    """
    Evaluate heuristic rules over decompiler features and return:
    {
      "schema": "rexis.baseline.heuristics.v1",
      "score": 0.73,
      "label": "malicious",
      "evidence": [
        {"id":"...", "title":"...", "detail":"...", "severity":"warn", "score": 0.2}
      ],
      "counts": {"info": 1, "warn": 2, "error": 1}
    }
    """
    print(
        f"[heuristics] Starting heuristic classification (min_sev={min_severity}, rules={rules_path or 'default'})"
    )
    rules: Dict[str, Any] = load_heuristic_rules(rules_path)

    # Collect evidence from built-in rules
    # Each rule returns (Evidence|None, miss_reason|None)
    ruleset: List[Tuple[str, Callable[[Dict[str, Any]], Tuple[Optional[Evidence], Optional[str]]]]] = [
        ("sus_api_combo", rule_suspicious_api_combination),
        ("packer_artifacts", rule_packer_artifacts),
        ("tiny_text_section", rule_tiny_text_section),
        ("low_entropy_strings", rule_low_entropy_strings),
        ("entry_in_writable", rule_entry_in_writable_section),
        ("networking_indicators", rule_networking_indicators),
        ("http_exfil_indicators", rule_http_exfil_indicators),
        ("crypto_indicators", rule_crypto_indicators),
        ("dynamic_api_resolution", rule_dynamic_api_resolution),
        ("shell_exec_indicators", rule_shell_execution_indicators),
        ("autorun_persistence", rule_autorun_persistence),
        ("service_persistence", rule_service_persistence),
        ("filesystem_mod", rule_filesystem_modification),
        ("suspicious_urls_in_strings", rule_suspicious_urls_in_strings),
        ("anti_vm_strings", rule_anti_vm_strings),
        ("dbg_anti_dbg", rule_debugger_anti_debug_indicators),
    ]

    all_ev: List[Evidence] = []
    hit_count: int = 0
    miss_reasons: List[Dict[str, str]] = []
    for rid, rule_fn in ruleset:
        if not is_rule_enabled(rid, rules):
            continue
        ev, miss = rule_fn(features)
        if ev:
            # Ensure the evidence id matches the configured rule id
            ev.id = rid
            all_ev.append(ev)
            hit_count += 1
            print(f"[heuristics] Rule hit: {rid} (sev={ev.severity}, score={ev.score:.2f})")
        else:
            reason = miss or "no hit"
            miss_reasons.append({"id": rid, "reason": reason})
            print(f"[heuristics] Rule miss: {rid} (reason={reason})")

    print(f"[heuristics] Rules evaluated: {len(ruleset)}, hits: {hit_count}")

    # Combine + label
    score: float = _combine_evidence_score(all_ev, rules)
    override_hits: List[str] = [ev.id for ev in all_ev]
    label: str = _label_from_combined_score(score, rules, override_hits)
    print(f"[heuristics] Combined score={score:.2f} → label={label}")

    # Filter evidence by min severity for the *returned* payload (score is computed on full set)
    returned_ev: List[Evidence] = [
        ev for ev in all_ev if severity_is_at_least(min_severity, ev.severity)
    ]
    counts: Dict[str, int] = {"info": 0, "warn": 0, "error": 0}
    for ev in returned_ev:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1
    if len(returned_ev) != len(all_ev):
        print(
            f"[heuristics] Evidence filtered by min severity: returned={len(returned_ev)} / total={len(all_ev)}"
        )
    print(
        f"[heuristics] Evidence counts: info={counts['info']}, warn={counts['warn']}, error={counts['error']}"
    )

    # Compute tags
    tag_scores: Dict[str, float] = _compute_tag_scores(all_ev, rules)
    tag_threshold: float = float(get_nested_value(rules, "tagging.threshold", 0.3) or 0.3)
    top_k: int = int(get_nested_value(rules, "tagging.top_k", 5) or 5)
    # sort by score desc then tag name asc for determinism
    sorted_tags: List[Tuple[str, float]] = sorted(
        ((t, s) for t, s in tag_scores.items() if s >= tag_threshold),
        key=lambda x: (-x[1], x[0]),
    )[: max(0, top_k)]
    print(
        f"[heuristics] Tags selected: {len(sorted_tags)} (threshold={tag_threshold:.2f}, top_k={top_k})"
    )

    result: Dict[str, Any] = {
        "schema": "rexis.baseline.heuristics.v1",
        "score": round(float(score), 4),
        "label": label,
        "evidence": [
            {
                "id": ev.id,
                "title": ev.title,
                "detail": ev.detail,
                "severity": ev.severity,
                "score": round(float(ev.score), 4),
            }
            for ev in returned_ev
        ],
        "counts": counts,
        "tags": [{"tag": tag, "score": round(float(s), 4)} for tag, s in sorted_tags],
        "rule_misses": miss_reasons,
    }
    return result
