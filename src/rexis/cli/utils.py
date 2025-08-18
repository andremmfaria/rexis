from pathlib import Path
import shutil
from typing import Dict, List, Optional

import typer


def parse_metadata_list(metadata: Optional[List[str]]) -> Dict[str, str]:
    metadata_dict: Dict[str, str] = {}
    if metadata:
        for item in metadata:
            if "=" not in item:
                raise typer.BadParameter(f"Metadata must be in key=value format: {item}")
            key, value = item.split("=", 1)
            key, value = key.strip(), value.strip()
            if key in metadata_dict:
                raise typer.BadParameter(f"Duplicate metadata key: '{key}'")
            metadata_dict[key] = value
    return metadata_dict


def validate_dir_or_file(dir: Optional[Path], file: Optional[Path]) -> None:
    provided: List[str] = [
        name for name, val in {"--dir": dir, "--file": file}.items() if val is not None
    ]
    if len(provided) != 1:
        raise typer.BadParameter("Exactly one of --dir or --file must be provided.")


def validate_file_type(value: str) -> str:
    allowed = {"pdf", "html", "text", "json"}
    if value not in allowed:
        raise typer.BadParameter(f"--type must be one of {allowed}.")
    return value


def find_repo_root(start: Optional[Path] = None) -> Path:
    """Find the repository root by locating pyproject.toml walking up from start/cwd."""
    cur: Path = (start or Path.cwd()).resolve()
    for p in [cur, *cur.parents]:
        if (p / "pyproject.toml").exists():
            return p
    # Fallback to current directory if pyproject not found
    return cur


def ensure_unique(dest_dir: Path, name: str) -> Path:
    """Return a unique destination path inside dest_dir using name, adding numeric suffix if needed."""
    base: str = Path(name).stem
    suffix: str = Path(name).suffix
    candidate: Path = dest_dir / f"{base}{suffix}"
    idx: int = 1
    while candidate.exists():
        candidate = dest_dir / f"{base}_{idx}{suffix}"
        idx += 1
    return candidate
