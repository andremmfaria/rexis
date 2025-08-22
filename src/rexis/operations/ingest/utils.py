import hashlib
from pathlib import Path
import sys
import threading
import time
from typing import List, Set

import pymupdf
from rexis.utils.utils import LOGGER


class Progress:
    def __init__(self, total: int, prefix: str = "INGEST") -> None:
        self.total = max(total, 1)
        self.done = 0
        self.prefix = prefix
        self.start_ts = time.time()
        self._lock = threading.Lock()

    def tick(self, n: int = 1) -> None:
        with self._lock:
            self.done += n
            print_progress(self.done, self.total, self.start_ts, self.prefix)


def print_progress(done: int, total: int, start_ts: float, prefix: str) -> None:
    try:
        total = max(total, 1)
        pct = min(max(done / total, 0.0), 1.0)
        bar_len = 28
        filled = int(bar_len * pct)
        bar = "#" * filled + "-" * (bar_len - filled)
        elapsed = max(time.time() - start_ts, 1e-6)
        rate = done / elapsed
        remaining = max(total - done, 0)
        eta = remaining / rate if rate > 0 else 0.0
        sys.stdout.write(
            f"\r[{prefix}] [{bar}] {done}/{total} ({pct*100:5.1f}%) | {rate:0.2f}/s | ETA: {eta:0.0f}s\n"
        )
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    except Exception:
        pass


def discover_paths(ftype: str, root: Path) -> List[Path]:
    exts: Set = {
        "pdf": {".pdf"},
        "html": {".html", ".htm"},
        "text": {".txt"},
        "json": {".json"},
    }[ftype]

    results: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            results.append(p)
    results.sort()
    print(f"Discovered {len(results)} {ftype} file(s) under {root}")
    return results


def pdf_to_text(path: Path) -> str:
    parts: List[str] = []
    try:
        with pymupdf.open(path) as doc:
            for page in doc:
                try:
                    parts.append(page.get_text("text"))
                except Exception as e:
                    LOGGER.warning(f"MuPDF warning on page extraction ({path}): {e}")
    except Exception as e:
        LOGGER.error(f"Failed to open PDF {path}: {e}")
        return ""
    return "\n".join(parts)


def stable_doc_id_from_path(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    digest = h.hexdigest()
    return digest


def normalize_whitespace(s: str) -> str:
    s = s.replace("\r", "")
    import re

    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()



