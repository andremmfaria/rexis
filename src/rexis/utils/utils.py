import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import tomli

LOGGER = logging.getLogger(__name__)


def setup_logging(verbosity: int):
    """
    Configure logging based on verbosity count.

    Verbosity mapping:
    - 0: ERROR (default)
    - 1: WARNING
    - 2: INFO
    - 3 or more: DEBUG
    """
    if verbosity <= 0:
        level = logging.ERROR
    elif verbosity == 1:
        level = logging.WARNING
    elif verbosity == 2:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
    )
    LOGGER.setLevel(level)
    if level == logging.DEBUG:
        LOGGER.debug("Verbosity level: %s (DEBUG)", verbosity)


def get_version() -> str:
    pyproject_path = os.path.join(os.path.dirname(__file__), "../../../pyproject.toml")
    with open(pyproject_path, "rb") as f:
        data = tomli.load(f)
    return data["project"]["version"]


def sha256(path: Path) -> str:
    h: "hashlib._Hash" = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(obj: Dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(obj, f, indent=2)
    return path


def load_json(path: Path) -> Dict:
    with path.open("r") as f:
        return json.load(f)


def safe_get(d: Dict[str, Any], path: List[Any], default: Any | None = None) -> Any:
    """Safely fetch a nested value from a dict using a list path.

    Example:
        safe_get(obj, ["a", "b", 0, "c"], default=None)
    """
    cur: Any = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iter_pe_files(root: Path) -> List[Path]:
    """Discover likely PE files by extension. Adjust if you want stricter checks."""
    exts: Set[str] = {".exe", ".dll", ".sys"}
    return [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts]


def wait_qpm(qpm: int, state: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """
    Simple rate limiter helper to enforce a maximum queries-per-minute (QPM).

    Usage:
        state = {}
        wait_qpm(30, state)  # blocks as needed, updates state["last"]

    Args:
        qpm: Max queries per minute (>=1). If <=0, will be treated as 1.
        state: Mutable dict used to track last call timestamp. If None, a new dict is created.

    Returns:
        The (possibly newly created) state dict with updated "last" timestamp.
    """
    interval: float = 60.0 / max(1, int(qpm))
    if state is None:
        state = {"last": 0.0}
    last: float = float(state.get("last", 0.0))
    now: float = time.time()
    delta: float = now - last
    if delta < interval:
        time.sleep(interval - delta)
    state["last"] = time.time()
    return state
