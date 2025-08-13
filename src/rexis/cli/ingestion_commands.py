from pathlib import Path
from typing import Dict, List, Optional, Tuple

import typer
from rexis.cli.utils import ensure_exactly_one, make_batches, validate_file_type
from rexis.operations.ingest.ingest_api import ingest_api_exec
from rexis.operations.ingest.ingest_file import ingest_file_exec
from rexis.utils.utils import LOGGER


def ingest_api(
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Tags to search for"),
    fetch_limit: Optional[int] = typer.Option(
        None, "--fetch-limit", "-l", help="How many entries to fetch from the API", min=1
    ),
    batch: Optional[int] = typer.Option(
        None, "--batch", "-b", help="Batch size to split results into", min=1
    ),
    hash: Optional[str] = typer.Option(None, "--hash", "-s", help="Single SHA256 hash to fetch"),
    hash_file: Optional[Path] = typer.Option(
        None,
        "--hash-file",
        "-f",
        exists=True,
        dir_okay=False,
        help="File with newline-separated hashes",
    ),
) -> None:
    choice: str = ensure_exactly_one(
        "api",
        tags=tags or None,
        hash=hash,
        hash_file=str(hash_file) if hash_file else None,
    )

    if choice == "tags":
        if fetch_limit is None or fetch_limit <= 0:
            raise typer.BadParameter("--fetch_limit must be provided and > 0 when using --tags.")
        if batch is None or batch <= 0:
            raise typer.BadParameter("--batch must be provided and > 0 when using --tags.")

        batches: List[Tuple[int, int]] = make_batches(fetch_limit, batch)
        print(
            "[API] Tags=%s | fetch_limit=%d | batch=%d | batches=%d",
            tags,
            fetch_limit,
            batch,
            len(batches),
        )
        for batch_index, (start_idx, end_idx) in enumerate(batches, 1):
            LOGGER.debug(
                "Batch %d: [start=%d, end=%d) size=%d",
                batch_index,
                start_idx,
                end_idx,
                end_idx - start_idx,
            )

        ingest_api_exec(tags=tags, fetch_limit=fetch_limit, batch=batch)

    elif choice == "hash":
        if any(v is not None for v in (fetch_limit, batch, hash_file)):
            raise typer.BadParameter(
                "--hash cannot be combined with --fetch_limit/--batch/--hash_file."
            )
        print("[API] Single hash=%s", hash)
        ingest_api_exec(hash=hash)

    elif choice == "hash_file":
        if any(v is not None for v in (fetch_limit, batch, hash)):
            raise typer.BadParameter(
                "--hash_file cannot be combined with --fetch_limit/--batch/--hash."
            )
        with open(hash_file, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
        print("[API] %d hashes loaded from %s", len(hashes), hash_file)
        ingest_api_exec(hash_file=hash_file)


def ingest_file(
    type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="File type to ingest: pdf, html, or text",
        show_choices=True,
        case_sensitive=False,
        callback=validate_file_type,
    ),
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single file to ingest",
    ),
    batch: int = typer.Option(
        50, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    provided: List[str] = [
        name for name, val in {"--dir": dir, "--file": file}.items() if val is not None
    ]
    if len(provided) != 1:
        raise typer.BadParameter("Exactly one of --dir or --file must be provided.")

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

    print(
        "[FILE] type=%s | mode=%s | batch=%d | metadata=%s",
        type,
        "dir" if dir else "file",
        batch,
        metadata_dict,
    )

    ingest_file_exec(
        ftype=type,
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
    )
