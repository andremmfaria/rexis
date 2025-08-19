from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone

from rexis.utils.types import FusionWeights, HeuristicsData, ReconcileConfig, ReconcilePolicyOverrides, Thresholds, VirusTotalData
from rexis.utils.utils import LOGGER


def clip_to_unit_interval(value: float) -> float:
    """Clamp a number to the [0.0, 1.0] interval."""
    return max(0.0, min(1.0, float(value)))


def epoch_seconds_to_iso_utc_date(epoch_seconds: Optional[int]) -> Optional[str]:
    """Convert epoch seconds to an ISO UTC date string (YYYY-MM-DD), or None on failure."""
    if not isinstance(epoch_seconds, int):
        return None
    try:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        LOGGER.error("Failed to convert epoch seconds to ISO date", exc_info=True)
        return None


def compute_heuristics_confidence(heuristics: HeuristicsData) -> Tuple[float, List[str]]:
    """Estimate heuristics confidence C_h in [0, 1] from evidence quality and diversity."""
    explanations: List[str] = []
    ev: List[EvidenceItem] = heuristics.get("evidence") or []  # type: ignore[assignment]
    if not isinstance(ev, list):
        ev = []

    sev_counts: Dict[str, int] = {"info": 0, "warn": 0, "error": 0}
    ids: Set[str] = set()
    for e in ev:
        sid: str = str(e.get("id", "")).lower()
        ids.add(sid)
        sev: str = str(e.get("severity", "info")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Independent categories derived from rule ids (coarse but useful)
    categories: Set[str] = set()
    cat_map: Dict[str, str] = {
        "sus_api_combo": "inj",
        "shell_exec_indicators": "inj",
        "entry_in_writable": "memsec",
        "networking_indicators": "net",
        "crypto_indicators": "crypto",
        "autorun_persistence": "persist",
        "dbg_anti_dbg": "anti",
        "packer_artifacts": "obf",
    }
    for rid in ids:
        categories.add(cat_map.get(rid, rid))

    base: float = 0.60
    if sev_counts["error"] > 0:
        base += 0.20
    elif sev_counts["warn"] > 0:
        base += 0.10

    # Diversity bonus
    if len(categories) >= 3:
        base += 0.10
    elif len(categories) >= 2:
        base += 0.05

    # Penalize if only obfuscation hits and little else
    if "packer_artifacts" in ids and (sev_counts["error"] + sev_counts["warn"]) < 2:
        base -= 0.15

    # No evidence at all => strong penalty
    if sum(sev_counts.values()) == 0:
        base -= 0.25

    C_h: float = clip_to_unit_interval(base)

    explanations.append(
        f"heuristics_confidence={C_h:.2f} (errors={sev_counts['error']}, "
        f"warns={sev_counts['warn']}, infos={sev_counts['info']}, "
        f"categories={len(categories)})"
    )
    if "packer_artifacts" in ids:
        explanations.append("packer indicators present → slight confidence reduction")
    return C_h, explanations


def compute_vt_score_and_confidence(
    vt: Optional[VirusTotalData], vt_error: Optional[str]
) -> Tuple[float, float, Dict[str, Any], List[str]]:
    """Compute VT consensus score S_vt and confidence C_vt in [0, 1]."""
    info: Dict[str, Any] = {}
    notes: List[str] = []

    if vt_error:
        notes.append(f"VT error: {vt_error}")
        return 0.0, 0.0, info, notes
    if not vt:
        notes.append("VT data not available")
        return 0.0, 0.0, info, notes

    mal: int = int(vt.get("malicious") or 0)
    sus: int = int(vt.get("suspicious") or 0)
    har: int = int(vt.get("harmless") or 0)
    und: int = int(vt.get("undetected") or 0)
    tout: int = int(vt.get("timeout") or 0)

    denom: int = max(0, mal + sus + har + tout)  # ignore 'undetected' in denominator
    if denom == 0:
        denom = max(1, mal + sus + har + tout + und)

    # Weighted consensus: suspicious counts half
    S_vt: float = clip_to_unit_interval((mal + 0.5 * sus) / float(denom))

    # Confidence
    base: float = 0.45 if denom < 5 else 0.60
    if mal >= 5:
        base += 0.10
    if denom >= 20:
        base += 0.10
    if mal <= 1 and S_vt < 0.20:
        base -= 0.10

    # Threat naming / taxonomy hint
    pop_name: Optional[str | List[str]] = vt.get("popular_threat_name")  # type: ignore[assignment]
    if isinstance(pop_name, list):
        pop_name = ", ".join([str(x) for x in pop_name[:3]])
    if pop_name:
        base += 0.05

    # Recency heuristic from last_submission_date (epoch seconds)
    last_ts: Optional[int] = vt.get("last_submission_date")  # type: ignore[assignment]
    if isinstance(last_ts, int):
        from datetime import datetime, timezone

        age_days: float = (datetime.now(timezone.utc).timestamp() - last_ts) / 86400.0
        if age_days <= 90:
            base += 0.05
        elif age_days >= 730:
            base -= 0.05
        info["last_submission_date"] = epoch_seconds_to_iso_utc_date(last_ts)

    C_vt: float = clip_to_unit_interval(base)

    info.update(
        {
            "malicious": mal,
            "suspicious": sus,
            "harmless": har,
            "undetected": und,
            "timeout": tout,
            "popular_threat_name": pop_name,
            "type_description": vt.get("type_description"),
            "meaningful_name": vt.get("meaningful_name"),
            "names": vt.get("names")[:10] if isinstance(vt.get("names"), list) else None,
            "size": vt.get("size"),
            "sha256": vt.get("sha256"),
            "consensus_denominator": denom,
            "consensus_score": round(S_vt, 4),
            "confidence": round(C_vt, 4),
        }
    )

    notes.append(
        f"vt_score={S_vt:.2f} vt_confidence={C_vt:.2f} (mal={mal}, sus={sus}, denom={denom})"
    )
    if denom < 5:
        notes.append("low engine coverage on VT → reduced confidence")
    return S_vt, C_vt, info, notes


def label_from_thresholds(fused_score: float, cfg: ReconcileConfig) -> str:
    if fused_score >= cfg.t_malicious:
        return "malicious"
    if fused_score >= cfg.t_suspicious:
        return "suspicious"
    return "benign"


def compute_disagreement_penalty(heuristics_score: float, vt_score: float, cfg: ReconcileConfig) -> float:
    gap: float = abs(heuristics_score - vt_score)
    if gap <= cfg.gap_penalty_start:
        return 0.0
    extra: float = gap - cfg.gap_penalty_start
    return clip_to_unit_interval(min(cfg.gap_penalty_max, cfg.gap_penalty_slope * extra))


def fuse_heuristics_and_virustotal_decision(
    *,
    heuristics: HeuristicsData,
    vt: Optional[VirusTotalData] = None,
    vt_error: Optional[str] = None,
    weights: Optional[FusionWeights] = None,  # {"w_h":0.5,"w_vt":0.5}
    thresholds: Optional[Thresholds] = None,  # {"malicious":0.7,"suspicious":0.4}
    policy: Optional[ReconcilePolicyOverrides] = None,  # overrides for gap/penalty settings
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
    Ch, h_notes = compute_heuristics_confidence(heuristics)

    # VT signal
    Svt, Cvt, vt_info, vt_notes = compute_vt_score_and_confidence(vt, vt_error)

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
    if (vt and not vt_error) and gap >= cfg.conflict_gap_hard and Ch >= cfg.high_conf and Cvt >= cfg.high_conf:
        fused = cfg.conflict_override_score
        conflict_override_applied = True

    label: str = label_from_thresholds(fused, cfg)

    # Build explanation
    expl: List[str] = []
    expl.extend(h_notes)
    expl.extend(vt_notes)
    if penalty > 0:
        expl.append(f"disagreement_penalty={penalty:.2f} due to gap={gap:.2f}")
    if conflict_override_applied:
        expl.append("hard conflict override applied → set fused score to mid value")

    result: Dict[str, Any] = {
        "schema": "rexis.baseline.decision.v1",
        "inputs": {
            "heuristics": {
                "score": round(Sh, 4),
                "label": heuristics.get("label"),
                "evidence_counts": {
                    "info": sum(1 for e in (heuristics.get("evidence") or []) if str(e.get("severity","")).lower()=="info"),
                    "warn": sum(1 for e in (heuristics.get("evidence") or []) if str(e.get("severity","")).lower()=="warn"),
                    "error": sum(1 for e in (heuristics.get("evidence") or []) if str(e.get("severity","")).lower()=="error"),
                },
            },
            "virustotal": vt_info if vt and not vt_error else {"error": vt_error or "not_available"},
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

