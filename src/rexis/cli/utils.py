from pathlib import Path
from typing import Dict, List, Optional
import typer


def _parse_metadata_list(metadata: Optional[List[str]]) -> Dict[str, str]:
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


def _validate_dir_or_file(dir: Optional[Path], file: Optional[Path]) -> None:
    provided: List[str] = [
        name for name, val in {"--dir": dir, "--file": file}.items() if val is not None
    ]
    if len(provided) != 1:
        raise typer.BadParameter("Exactly one of --dir or --file must be provided.")


def _validate_file_type(value: str):
    allowed = {"pdf", "html", "text", "json"}
    if value not in allowed:
        raise typer.BadParameter(f"--type must be one of {allowed}.")
    return value
