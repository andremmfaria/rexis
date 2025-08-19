import hashlib
from pathlib import Path
from typing import List, Set

import pymupdf
from rexis.utils.utils import LOGGER


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
