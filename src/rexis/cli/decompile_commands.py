import shutil
from pathlib import Path
from typing import Optional

import typer
from rexis.operations.decompile import trigger_import_and_analysis


def _find_repo_root(start: Optional[Path] = None) -> Path:
    """Find the repository root by locating pyproject.toml walking up from start/cwd."""
    cur = (start or Path.cwd()).resolve()
    for p in [cur, *cur.parents]:
        if (p / "pyproject.toml").exists():
            return p
    # Fallback to current directory if pyproject not found
    return cur


def _ensure_unique(dest_dir: Path, name: str) -> Path:
    """Return a unique destination path inside dest_dir using name, adding numeric suffix if needed."""
    base = Path(name).stem
    suffix = Path(name).suffix
    candidate = dest_dir / f"{base}{suffix}"
    idx = 1
    while candidate.exists():
        candidate = dest_dir / f"{base}_{idx}{suffix}"
        idx += 1
    return candidate


def _copy_into_samples(src: Path, samples_dir: Path, overwrite: bool) -> Path:
    samples_dir.mkdir(parents=True, exist_ok=True)
    dest = samples_dir / src.name
    if dest.exists() and not overwrite:
        dest = _ensure_unique(samples_dir, src.name)
    shutil.copy2(src, dest)
    return dest


def decompile_binary(
    file: Path = typer.Option(
        ...,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Path to the binary to decompile",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        "-o",
        help="Overwrite if a file with the same name already exists in samples dir",
    ),
) -> None:
    """
    Decompile/analyze a binary using the Ghidra API service configured in docker-compose.

    This command copies the provided file into the mounted samples directory so it is visible
    to the Ghidra API containers, then invokes the import+analysis tool exposed by the API.

    Environment:
      - GHIDRA_API_URL: Base URL for the API gateway (default http://localhost:8000)
      - MCPO_API_KEY: API key for the service (default top-secret)
    """
    repo_root = _find_repo_root()
    samples_dir = repo_root / "data" / "ghidra" / "samples"

    # If the file is already inside the samples dir, skip copy
    try:
        file_resolved = file.resolve()
        if samples_dir in file_resolved.parents:
            dest = file_resolved
        else:
            dest = _copy_into_samples(file_resolved, samples_dir, overwrite)
    except Exception as e:
        raise typer.BadParameter(f"Failed to prepare sample file: {e}")

    container_path = f"/binaries/{dest.name}"
    print(f"Invoking Ghidra import+analysis for {container_path} (from {dest})...")
    try:
        result = trigger_import_and_analysis(container_path)
    except Exception as e:
        raise typer.Exit(code=1) from e

    # Pretty-print a concise summary; full JSON can be large, so print minimal fields if present
    # Fall back to raw print if structure unknown
    try:
        import json as _json

        print(_json.dumps(result, indent=2))
    except Exception:
        print(str(result))
