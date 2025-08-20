from typing import Any, Dict, List, Optional, Set, Tuple

from rexis.tools.decision.constants import (
    CAT_MAP,
    DIVERSITY_BONUS_2,
    DIVERSITY_BONUS_3,
    HEUR_BASE,
    HEUR_ERROR_BOOST,
    HEUR_WARN_BOOST,
    NO_EVIDENCE_PENALTY,
    PACKER_ONLY_PENALTY,
    VT_BASE_DEFAULT,
    VT_BASE_LOW_COVERAGE,
    VT_DENOM_GE_BONUS,
    VT_DENOM_GE_BONUS_COUNT,
    VT_LOW_COVERAGE_DENOM_THRESHOLD,
    VT_LOW_MAL_LOW_SCORE,
    VT_LOW_MAL_MAX,
    VT_LOW_MAL_PENALTY,
    VT_MAL_GE_BONUS,
    VT_MAL_GE_BONUS_COUNT,
    VT_OLD_DAYS_THRESHOLD,
    VT_OLD_PENALTY,
    VT_RECENT_BONUS,
    VT_RECENT_DAYS_THRESHOLD,
    VT_SUSP_WEIGHT,
    VT_THREAT_NAME_BONUS,
)
from rexis.tools.decision.utils import clip_to_unit_interval, epoch_seconds_to_iso_utc_date
from rexis.utils.types import (
    EvidenceItem,
    HeuristicsData,
    ReconcileConfig,
    VirusTotalData,
)


def compute_heuristics_confidence(
    heuristics: HeuristicsData,
    conf_cfg: Optional[Dict[str, float]] = None,
    cat_map_override: Optional[Dict[str, str]] = None,
) -> Tuple[float, List[str]]:
    """Estimate heuristics confidence C_h in [0, 1] from evidence quality and diversity.

    Optional overrides via conf_cfg (keys: base, error_boost, warn_boost,
    diversity_bonus_3, diversity_bonus_2, packer_only_penalty, no_evidence_penalty).
    Category mapping can be overridden via cat_map_override.
    """
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
    active_cat_map: Dict[str, str] = cat_map_override or CAT_MAP
    for rid in ids:
        categories.add(active_cat_map.get(rid, rid))

    base: float = float((conf_cfg or {}).get("base", HEUR_BASE))
    if sev_counts["error"] > 0:
        base += float((conf_cfg or {}).get("error_boost", HEUR_ERROR_BOOST))
    elif sev_counts["warn"] > 0:
        base += float((conf_cfg or {}).get("warn_boost", HEUR_WARN_BOOST))

    # Diversity bonus
    if len(categories) >= 3:
        base += float((conf_cfg or {}).get("diversity_bonus_3", DIVERSITY_BONUS_3))
    elif len(categories) >= 2:
        base += float((conf_cfg or {}).get("diversity_bonus_2", DIVERSITY_BONUS_2))

    # Penalize if only obfuscation hits and little else
    if "packer_artifacts" in ids and (sev_counts["error"] + sev_counts["warn"]) < 2:
        base -= float((conf_cfg or {}).get("packer_only_penalty", PACKER_ONLY_PENALTY))

    # No evidence at all => strong penalty
    if sum(sev_counts.values()) == 0:
        base -= float((conf_cfg or {}).get("no_evidence_penalty", NO_EVIDENCE_PENALTY))

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

    denom: int = max(0, mal + sus + har)  # ignore 'undetected' in denominator
    if denom == 0:
        denom = max(1, mal + sus + har + und)

    # Weighted consensus: suspicious counts half
    S_vt: float = clip_to_unit_interval((mal + VT_SUSP_WEIGHT * sus) / float(denom))

    # Confidence
    base: float = (
        VT_BASE_LOW_COVERAGE if denom < VT_LOW_COVERAGE_DENOM_THRESHOLD else VT_BASE_DEFAULT
    )
    if mal >= VT_MAL_GE_BONUS_COUNT:
        base += VT_MAL_GE_BONUS
    if denom >= VT_DENOM_GE_BONUS_COUNT:
        base += VT_DENOM_GE_BONUS
    if mal <= VT_LOW_MAL_MAX and S_vt < VT_LOW_MAL_LOW_SCORE:
        base -= VT_LOW_MAL_PENALTY

    # Threat naming / taxonomy hint
    pop_name: Optional[str | List[str]] = vt.get("popular_threat_name")  # type: ignore[assignment]
    if isinstance(pop_name, list):
        pop_name = ", ".join([str(x) for x in pop_name[:3]])
    if pop_name:
        base += VT_THREAT_NAME_BONUS

    # Recency heuristic from last_submission_date (epoch seconds)
    last_ts: Optional[int] = vt.get("last_submission_date")  # type: ignore[assignment]
    if isinstance(last_ts, int):
        from datetime import datetime, timezone

        age_days: float = (datetime.now(timezone.utc).timestamp() - last_ts) / 86400.0
        if age_days <= VT_RECENT_DAYS_THRESHOLD:
            base += VT_RECENT_BONUS
        elif age_days >= VT_OLD_DAYS_THRESHOLD:
            base -= VT_OLD_PENALTY
        info["last_submission_date"] = epoch_seconds_to_iso_utc_date(last_ts)

    C_vt: float = clip_to_unit_interval(base)

    info.update(
        {
            "malicious": mal,
            "suspicious": sus,
            "harmless": har,
            "undetected": und,
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



def compute_disagreement_penalty(
    heuristics_score: float, vt_score: float, cfg: ReconcileConfig
) -> float:
    gap: float = abs(heuristics_score - vt_score)
    if gap <= cfg.gap_penalty_start:
        return 0.0
    extra: float = gap - cfg.gap_penalty_start
    return clip_to_unit_interval(min(cfg.gap_penalty_max, cfg.gap_penalty_slope * extra))
