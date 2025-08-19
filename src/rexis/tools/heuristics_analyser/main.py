from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from rexis.tools.heuristics_analyser.rules import (
    rule_autorun_persistence,
    rule_crypto_indicators,
    rule_debugger_anti_debug_indicators,
    rule_entry_in_writable_section,
    rule_networking_indicators,
    rule_packer_artifacts,
    rule_shell_execution_indicators,
    rule_suspicious_api_combination,
    rule_tiny_text_section,
    rule_low_entropy_strings,
    rule_dynamic_api_resolution,
    rule_service_persistence,
    rule_filesystem_modification,
    rule_suspicious_urls_in_strings,
    rule_anti_vm_strings,
    rule_http_exfil_indicators,
)
from rexis.tools.heuristics_analyser.utils import (
    get_nested_value,
    is_rule_enabled,
    load_heuristic_rules,
    severity_is_at_least,
)
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
    rules: Dict[str, Any] = load_heuristic_rules(rules_path)

    # Collect evidence from built-in rules
    ruleset: List[Tuple[str, Callable[[Dict[str, Any]], Optional[Evidence]]]] = [
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
    for rid, rule_fn in ruleset:
        if not is_rule_enabled(rid, rules):
            continue
        ev: Optional[Evidence] = rule_fn(features)
        if ev:
            # Ensure the evidence id matches the configured rule id
            ev.id = rid
            all_ev.append(ev)

    # Combine + label
    score: float = _combine_evidence_score(all_ev, rules)
    override_hits: List[str] = [ev.id for ev in all_ev]
    label: str = _label_from_combined_score(score, rules, override_hits)

    # Filter evidence by min severity for the *returned* payload (score is computed on full set)
    returned_ev: List[Evidence] = [
        ev for ev in all_ev if severity_is_at_least(min_severity, ev.severity)
    ]
    counts: Dict[str, int] = {"info": 0, "warn": 0, "error": 0}
    for ev in returned_ev:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1

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
    }
    return result
