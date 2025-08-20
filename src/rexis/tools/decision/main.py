from typing import Any, Dict, List, Optional

from rexis.tools.decision.compute import (
    compute_disagreement_penalty,
    compute_heuristics_confidence,
    compute_vt_score_and_confidence,
)
from rexis.tools.decision.constants import CH_CEIL, CH_FLOOR, CVT_CEIL, CVT_FLOOR, Label
from rexis.tools.decision.utils import clip_to_unit_interval, label_from_thresholds
from rexis.utils.types import (
    FusionWeights,
    HeuristicsData,
    ReconcileConfig,
    ReconcilePolicyOverrides,
    Thresholds,
    VirusTotalData,
)


def fuse_heuristics_and_virustotal_decision(
    heuristics: HeuristicsData,
    vt: Optional[VirusTotalData] = None,
    vt_error: Optional[str] = None,
    weights: Optional[FusionWeights] = None,
    thresholds: Optional[Thresholds] = None,
    policy: Optional[ReconcilePolicyOverrides] = None,
) -> Dict[str, Any]:
    """
    Fuse heuristics output with (optional) VirusTotal data using a confidence-based strategy.

    Returns a dict with schema "rexis.baseline.decision.v1" containing:
      - inputs.{heuristics, virustotal}
      - confidence.{C_h, C_vt}
      - weights.{w_h, w_vt}
      - fusion.{gap, penalty, conflict_override_applied}
      - final.{score, label, thresholds}
      - explanation: list[str]
    """
    # Config
    cfg = ReconcileConfig()
    if weights:
        if "w_h" in weights:
            cfg.w_h = float(weights["w_h"])
        if "w_vt" in weights:
            cfg.w_vt = float(weights["w_vt"])
    if thresholds:
        if "malicious" in thresholds:
            cfg.t_malicious = float(thresholds["malicious"])
        if "suspicious" in thresholds:
            cfg.t_suspicious = float(thresholds["suspicious"])
    if policy:
        cfg.gap_penalty_start = float(policy.get("gap_penalty_start", cfg.gap_penalty_start))
        cfg.gap_penalty_max = float(policy.get("gap_penalty_max", cfg.gap_penalty_max))
        cfg.gap_penalty_slope = float(policy.get("gap_penalty_slope", cfg.gap_penalty_slope))
        cfg.conflict_gap_hard = float(policy.get("conflict_gap_hard", cfg.conflict_gap_hard))
        cfg.high_conf = float(policy.get("high_conf", cfg.high_conf))
        cfg.conflict_override_score = float(
            policy.get("conflict_override_score", cfg.conflict_override_score)
        )

    # Heuristics signal
    Sh: float = clip_to_unit_interval(float(heuristics.get("score") or 0.0))
    # Policy-driven overrides for heuristics confidence and category mapping
    heur_conf_overrides: Optional[Dict[str, float]] = None
    cat_map_override: Optional[Dict[str, str]] = None
    if policy:
        try:
            heur_conf_overrides = policy.get("heuristics_conf")  # type: ignore[assignment]
        except Exception:
            heur_conf_overrides = None
        try:
            cat_map_override = policy.get("cat_map")  # type: ignore[assignment]
        except Exception:
            cat_map_override = None
    Ch, h_notes = compute_heuristics_confidence(heuristics, heur_conf_overrides, cat_map_override)

    # VT signal
    Svt, Cvt, vt_info, vt_notes = compute_vt_score_and_confidence(vt, vt_error)

    # Confidence floors/ceilings (policy overridable)
    C_h_floor: float = CH_FLOOR
    C_h_ceil: float = CH_CEIL
    C_vt_floor: float = CVT_FLOOR
    C_vt_ceil: float = CVT_CEIL
    if policy:
        try:
            C_h_floor = float(policy.get("C_h_floor", C_h_floor))
            C_h_ceil = float(policy.get("C_h_ceil", C_h_ceil))
            C_vt_floor = float(policy.get("C_vt_floor", C_vt_floor))
            C_vt_ceil = float(policy.get("C_vt_ceil", C_vt_ceil))
        except Exception:
            pass
    Ch = max(C_h_floor, min(C_h_ceil, Ch))
    Cvt = max(C_vt_floor, min(C_vt_ceil, Cvt))

    # Fusion
    w_h: float = float(cfg.w_h)
    w_vt: float = float(cfg.w_vt)

    fused: float = w_h * Ch * Sh + w_vt * Cvt * Svt

    # Disagreement penalty
    gap: float = abs(Sh - Svt)
    penalty: float = compute_disagreement_penalty(Sh, Svt, cfg) if (vt and not vt_error) else 0.0
    fused = clip_to_unit_interval(fused - penalty)

    # Extreme conflict override: high-confidence, large-gap disagreement → abstain to "suspicious"
    conflict_override_applied: bool = False
    abstain_on_conflict: bool = True
    if policy:
        try:
            abstain_on_conflict = bool(policy.get("abstain_on_conflict", True))
        except Exception:
            abstain_on_conflict = True
    forced_label: Optional[Label] = None
    if (
        (vt and not vt_error)
        and gap >= cfg.conflict_gap_hard
        and Ch >= cfg.high_conf
        and Cvt >= cfg.high_conf
    ):
        fused = cfg.conflict_override_score
        conflict_override_applied = True
        if abstain_on_conflict:
            forced_label = Label.ABSTAIN
        else:
            forced_label = Label.SUSPICIOUS

    label: str = label_from_thresholds(fused, cfg)
    if forced_label is not None:
        label = forced_label

    # Build explanation
    expl: List[str] = []
    expl.extend(h_notes)
    expl.extend(vt_notes)
    if penalty > 0:
        expl.append(f"disagreement_penalty={penalty:.2f} due to gap={gap:.2f}")
    if conflict_override_applied:
        if forced_label == Label.ABSTAIN:
            expl.append("hard conflict override → abstain (set fused score to mid value)")
        else:
            expl.append("hard conflict override applied → set fused score to mid value")

    result: Dict[str, Any] = {
        "schema": "rexis.baseline.decision.v1",
        "inputs": {
            "heuristics": {
                "score": round(Sh, 4),
                "label": heuristics.get("label"),
                "evidence_counts": {
                    "info": sum(
                        1
                        for e in (heuristics.get("evidence") or [])
                        if str(e.get("severity", "")).lower() == "info"
                    ),
                    "warn": sum(
                        1
                        for e in (heuristics.get("evidence") or [])
                        if str(e.get("severity", "")).lower() == "warn"
                    ),
                    "error": sum(
                        1
                        for e in (heuristics.get("evidence") or [])
                        if str(e.get("severity", "")).lower() == "error"
                    ),
                },
            },
            "virustotal": (
                vt_info if vt and not vt_error else {"error": vt_error or "not_available"}
            ),
        },
        "confidence": {
            "C_h": round(Ch, 4),
            "C_vt": round(Cvt, 4),
        },
        "weights": {
            "w_h": round(w_h, 4),
            "w_vt": round(w_vt, 4),
        },
        "fusion": {
            "gap": round(gap, 4),
            "penalty": round(penalty, 4),
            "conflict_override_applied": conflict_override_applied,
        },
        "final": {
            "score": round(fused, 4),
            "label": label,
            "thresholds": {
                "malicious": cfg.t_malicious,
                "suspicious": cfg.t_suspicious,
            },
        },
        "explanation": expl,
    }
    return result
