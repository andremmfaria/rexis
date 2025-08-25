import glob
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from rexis.utils.constants import CATEGORIES


def truth_category_from_path(path: str) -> Optional[str]:
    run_dir_name = os.path.basename(os.path.dirname(path))
    lower_name = run_dir_name.lower()
    if "-analysis-" not in lower_name:
        return None
    try:
        after_analysis = lower_name.split("-analysis-", 1)[1]
        if "-run" in after_analysis:
            category = after_analysis.split("-run", 1)[0]
        else:
            category = after_analysis.split("-", 1)[0]
        category = category.strip().lower()
        return category if category in CATEGORIES else None
    except Exception:
        return None


def load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return None


def scan_reports(globs: List[str]) -> List[str]:
    paths: List[str] = []
    for pattern in globs:
        matches = glob.glob(pattern)
        if matches:
            for match in matches:
                if os.path.isdir(match):
                    paths.extend(glob.glob(os.path.join(match, "*.report.json")))
                    paths.extend(glob.glob(os.path.join(match, "*.json")))
                elif os.path.isfile(match) and match.endswith(".json"):
                    paths.append(match)
        else:
            paths.extend(glob.glob(os.path.join(pattern, "*.report.json")))
            paths.extend(glob.glob(os.path.join(pattern, "*.json")))
    return sorted(set(paths))


def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    phat = successes / total
    denom = 1 + z * z / total
    center = (phat + z * z / (2 * total)) / denom
    margin = z * ((phat * (1 - phat) + z * z / (4 * total)) / total) ** 0.5 / denom
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return lo, hi
