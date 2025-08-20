from datetime import datetime, timezone
from typing import Optional

from rexis.tools.decision.constants import Label
from rexis.utils.types import ReconcileConfig
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


def label_from_thresholds(fused_score: float, cfg: ReconcileConfig) -> str:
    if fused_score >= cfg.t_malicious:
        return Label.MALICIOUS
    if fused_score >= cfg.t_suspicious:
        return Label.SUSPICIOUS
    return Label.BENIGN
