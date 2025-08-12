import pathlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import typer
from rexis.cli.utils import ensure_exactly_one, make_batches, validate_file_type
from rexis.operations.collect_malpedia import collect_malpedia_exec
from rexis.operations.ingest_api import ingest_api_exec
from rexis.operations.ingest_file import ingest_file_exec
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
):
    """
    Ingest data from the MalwareBazaar API with strict parameter validation.

    Exactly one of --tags, --hash, or --hash_file must be provided.

    Modes:
    - --tags: Fetches entries matching the given tags. Requires both --fetch_limit (>0) and --batch (>0).
      The results will be split into batches of the specified size.
    - --hash: Fetches metadata for a single SHA256 hash. Cannot be combined with other options.
    - --hash_file: Fetches metadata for multiple hashes Listed in a file (one per line).
      Cannot be combined with other options.

    Parameters:
        tags: List of tags to search for (mutually exclusive with --hash and --hash_file).
        fetch_limit: Number of entries to fetch when using --tags (required for --tags).
        batch: Batch size for splitting results when using --tags (required for --tags).
        hash: Single SHA256 hash to fetch (mutually exclusive with --tags and --hash_file).
        hash_file: Path to a file containing hashes (mutually exclusive with --tags and --hash).

    Raises:
        typer.BadParameter: If parameter constraints are violated.
    """
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
        LOGGER.info(
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
        LOGGER.info("[API] Single hash=%s", hash)
        ingest_api_exec(hash=hash)

    elif choice == "hash_file":
        if any(v is not None for v in (fetch_limit, batch, hash)):
            raise typer.BadParameter(
                "--hash_file cannot be combined with --fetch_limit/--batch/--hash."
            )
        with open(hash_file, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
        LOGGER.info("[API] %d hashes loaded from %s", len(hashes), hash_file)
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
):
    """
    Ingest local files already on disk.
    Exactly one of --dir or --file must be provided.
    """
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

    LOGGER.info(
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


def collect_malpedia(
    family_id: Optional[str] = typer.Option(
        None, "--family-id", "-f", help="Malpedia family ID (e.g., win.cobalt_strike)"
    ),
    actor_id: Optional[str] = typer.Option(
        None, "--actor-id", "-a", help="Malpedia actor ID (e.g., apt.turla)"
    ),
    search_term: Optional[str] = typer.Option(
        None, "--search-term", "-s", help="Search term (e.g., CobaltStrike)"
    ),
    start_date: Optional[str] = typer.Option(
        None, "--start-date", help="Start date (YYYY-MM-DD) filter"
    ),
    end_date: Optional[str] = typer.Option(None, "--end-date", help="End date (YYYY-MM-DD) filter"),
    max_items: Optional[int] = typer.Option(
        None, "--max", help="Max items to keep after filtering"
    ),
    output_path: pathlib.Path = typer.Option(
        pathlib.Path("malpedia_urls.json"), "--output-path", "-o", help="Output file path"
    ),
):
    """
    Collect Malpedia references with AND/inner-join semantics:

    - If any of -f/-a/-s provided: fetch each set separately via API, then INTERSECT by URL.
    - If none provided: fall back to RSS 'latest'.
    - Apply --start_date/--end_date as an additional AND filter on dates.
    - Apply --max at the end.
    """

    try:
        num_saved: int = collect_malpedia_exec(
            family_id=family_id,
            actor_id=actor_id,
            search_term=search_term,
            start_date=start_date,
            end_date=end_date,
            max_items=max_items,
            output_path=output_path,
        )
    except ValueError as error:
        raise typer.BadParameter(str(error))
    typer.echo(f"Saved {num_saved} {'JSON objects' if format=='json' else 'rows'} to {output_path}")
