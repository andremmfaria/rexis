from typing import Any, Dict, List, Optional

from rexis.tools.reconciliation.compute import (
    compute_disagreement_penalty,
    compute_heuristics_confidence,
    compute_vt_score_and_confidence,
)
from rexis.tools.reconciliation.constants import (
    CH_CEIL,
    CH_FLOOR,
    CVT_CEIL,
    CVT_FLOOR,
    DECISION_CONFIG_DEFAULTS,
    LABEL_ABSTAIN,
    LABEL_SUSPICIOUS,
)
from rexis.tools.reconciliation.utils import clip_to_unit_interval, label_from_thresholds
from rexis.utils.types import (
    FusionWeights,
    HeuristicsData,
    ReconcileConfig,
    ReconcilePolicyOverrides,
    Thresholds,
    VirusTotalData,
)
from rexis.utils.utils import LOGGER


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
    print("[decision] Starting fusion: heuristics + VirusTotal")
    cfg = ReconcileConfig(**DECISION_CONFIG_DEFAULTS)
    if weights:
        if "w_h" in weights:
            cfg.heuristics_weight = float(weights["w_h"])
        if "w_vt" in weights:
            cfg.virustotal_weight = float(weights["w_vt"])
    if thresholds:
        if "malicious" in thresholds:
            cfg.threshold_malicious = float(thresholds["malicious"])
        if "suspicious" in thresholds:
            cfg.threshold_suspicious = float(thresholds["suspicious"])
    if policy:
        cfg.gap_penalty_start = float(policy.get("gap_penalty_start", cfg.gap_penalty_start))
        cfg.gap_penalty_max = float(policy.get("gap_penalty_max", cfg.gap_penalty_max))
        cfg.gap_penalty_slope = float(policy.get("gap_penalty_slope", cfg.gap_penalty_slope))
        cfg.conflict_gap_hard = float(policy.get("conflict_gap_hard", cfg.conflict_gap_hard))
        cfg.high_confidence = float(policy.get("high_conf", cfg.high_confidence))
        cfg.conflict_override_score = float(
            policy.get("conflict_override_score", cfg.conflict_override_score)
        )
    print(
        f"[decision] Configuration: heuristics_weight (w_h)={cfg.heuristics_weight:.2f}, "
        f"virustotal_weight (w_vt)={cfg.virustotal_weight:.2f}, "
        f"thresholds(malicious={cfg.threshold_malicious:.2f}, suspicious={cfg.threshold_suspicious:.2f})"
    )

    # Heuristics signal
    heuristics_score: float = clip_to_unit_interval(float(heuristics.get("score") or 0.0))
    print(f"[decision] Heuristics signal: score (Sh)={heuristics_score:.2f}")
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
    heuristics_confidence, heuristics_notes = compute_heuristics_confidence(
        heuristics, heur_conf_overrides, cat_map_override
    )
    print(f"[decision] Heuristics confidence: C_h={heuristics_confidence:.2f}")

    # VT signal
    virustotal_score, virustotal_confidence, virustotal_info, virustotal_notes = (
        compute_vt_score_and_confidence(vt, vt_error)
    )
    if vt_error:
        print(f"[decision] VirusTotal unavailable: vt_error='{vt_error}'")
    elif not vt:
        print("[decision] VT data not provided")
    else:
        print(
            f"[decision] VirusTotal signal: score (S_vt)={virustotal_score:.2f}, "
            f"confidence (C_vt)={virustotal_confidence:.2f}"
        )

    # Confidence floors/ceilings (policy overridable)
    heuristics_confidence_floor: float = CH_FLOOR
    heuristics_confidence_ceiling: float = CH_CEIL
    virustotal_confidence_floor: float = CVT_FLOOR
    virustotal_confidence_ceiling: float = CVT_CEIL
    if policy:
        try:
            heuristics_confidence_floor = float(
                policy.get("C_h_floor", heuristics_confidence_floor)
            )
            heuristics_confidence_ceiling = float(
                policy.get("C_h_ceil", heuristics_confidence_ceiling)
            )
            virustotal_confidence_floor = float(
                policy.get("C_vt_floor", virustotal_confidence_floor)
            )
            virustotal_confidence_ceiling = float(
                policy.get("C_vt_ceil", virustotal_confidence_ceiling)
            )
        except Exception:
            LOGGER.error("Error occurred while applying policy overrides")
            pass
    previous_heuristics_confidence, previous_virustotal_confidence = (
        heuristics_confidence,
        virustotal_confidence,
    )
    heuristics_confidence = max(
        heuristics_confidence_floor, min(heuristics_confidence_ceiling, heuristics_confidence)
    )
    virustotal_confidence = max(
        virustotal_confidence_floor, min(virustotal_confidence_ceiling, virustotal_confidence)
    )
    if (
        heuristics_confidence != previous_heuristics_confidence
        or virustotal_confidence != previous_virustotal_confidence
    ):
        print(
            f"[decision] Confidence clamped: C_h={heuristics_confidence:.2f} "
            f"(previous={previous_heuristics_confidence:.2f}), "
            f"C_vt={virustotal_confidence:.2f} (previous={previous_virustotal_confidence:.2f})"
        )

    # Fusion
    heuristics_weight: float = float(cfg.heuristics_weight)
    virustotal_weight: float = float(cfg.virustotal_weight)

    pre_reconciliation_score: float = (
        heuristics_weight * heuristics_confidence * heuristics_score
        + virustotal_weight * virustotal_confidence * virustotal_score
    )
    reconciliation_score: float = pre_reconciliation_score

    # Disagreement penalty
    score_gap: float = abs(heuristics_score - virustotal_score)
    disagreement_penalty: float = (
        compute_disagreement_penalty(heuristics_score, virustotal_score, cfg)
        if (vt and not vt_error)
        else 0.0
    )
    reconciliation_score = clip_to_unit_interval(reconciliation_score - disagreement_penalty)
    print(
        f"[decision] Reconciliation: pre_reconciliation_score={pre_reconciliation_score:.2f}, "
        f"score_gap(|Sh-S_vt|)={abs(heuristics_score - virustotal_score):.2f}, "
        f"disagreement_penalty={disagreement_penalty:.2f} -> post_fused_score={reconciliation_score:.2f}"
    )

    # Extreme conflict override: high-confidence, large-gap disagreement -> abstain to "suspicious"
    conflict_override_applied: bool = False
    abstain_on_conflict: bool = True
    if policy:
        try:
            abstain_on_conflict = bool(policy.get("abstain_on_conflict", True))
        except Exception:
            abstain_on_conflict = True
    forced_label: Optional[str] = None
    if (
        (vt and not vt_error)
        and score_gap >= cfg.conflict_gap_hard
        and heuristics_confidence >= cfg.high_confidence
        and virustotal_confidence >= cfg.high_confidence
    ):
        reconciliation_score = cfg.conflict_override_score
        conflict_override_applied = True
        if abstain_on_conflict:
            forced_label = LABEL_ABSTAIN
        else:
            forced_label = LABEL_SUSPICIOUS
        print(
            f"[decision] Hard conflict override applied: gap={score_gap:.2f}, "
            f"C_h={heuristics_confidence:.2f}, C_vt={virustotal_confidence:.2f} -> "
            f"forced_label={forced_label}, forced_score={reconciliation_score:.2f}"
        )

    label: str = label_from_thresholds(reconciliation_score, cfg)
    if forced_label is not None:
        label = forced_label
    print(f"[decision] Final decision: final_fused_score={reconciliation_score:.2f}, label={label}")

    # Build explanation
    expl: List[str] = []
    expl.extend(heuristics_notes)
    expl.extend(virustotal_notes)
    if disagreement_penalty > 0:
        expl.append(f"disagreement_penalty={disagreement_penalty:.2f} due to gap={score_gap:.2f}")
    if conflict_override_applied:
        if forced_label == LABEL_ABSTAIN:
            expl.append("hard conflict override -> abstain (set fused score to mid value)")
        else:
            expl.append("hard conflict override applied -> set fused score to mid value")

    result: Dict[str, Any] = {
        "schema": "rexis.baseline.decision.v1",
        "inputs": {
            "heuristics": {
                "score": round(heuristics_score, 4),
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
                virustotal_info if vt and not vt_error else {"error": vt_error or "not_available"}
            ),
        },
        "confidence": {
            "heuristics_confidence": round(heuristics_confidence, 4),
            "virustotal_confidence": round(virustotal_confidence, 4),
        },
        "weights": {
            "heuristics_weight": round(heuristics_weight, 4),
            "virustotal_weight": round(virustotal_weight, 4),
        },
        "comparison": {
            "conflict_override_applied": conflict_override_applied,
            "score_gap": round(score_gap, 4),
            "disagreement_penalty": round(disagreement_penalty, 4),
        },
        "final": {
            "score": round(reconciliation_score, 4),
            "label": label,
            "thresholds": {
                "malicious": cfg.threshold_malicious,
                "suspicious": cfg.threshold_suspicious,
            },
            "decision_thresholds": {
                "malicious": cfg.threshold_malicious,
                "suspicious": cfg.threshold_suspicious,
            },
        },
        "explanation": expl,
    }
    return result
