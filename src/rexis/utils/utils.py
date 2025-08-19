import time
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Set

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


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def iter_pe_files(root: Path) -> List[Path]:
    """Discover likely PE files by extension. Adjust if you want stricter checks."""
    exts: Set[str] = {".exe", ".dll", ".sys"}
    return [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts]
