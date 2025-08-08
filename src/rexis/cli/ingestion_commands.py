from pathlib import Path
from typing import Optional

import click
import typer
from rexis.cli.utils import ensure_exactly_one, make_batches
from rexis.operations.ingest_malwarebazaar import ingest_malwarebazaar_exec
from rexis.operations.ingest_vxunderground import ingest_vxunderground_exec
from rexis.utils.utils import LOGGER


def ingest_malwarebazaar(
    tags: Optional[str] = typer.Option(None, help="Tags to search for"),
    fetch_limit: Optional[int] = typer.Option(None, help="How many entries to fetch from the API"),
    batch: Optional[int] = typer.Option(None, help="Batch size to split results into"),
    hash: Optional[str] = typer.Option(None, help="Single SHA256 hash to fetch"),
    hash_file: Optional[Path] = typer.Option(
        None, exists=True, dir_okay=False, help="File with newline-separated hashes"
    ),
):
    """
    Ingest data from MalwareBazaar with strict parameter validation.

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
    choice = ensure_exactly_one(
        "malwarebazaar",
        tags=tags or None,
        hash=hash,
        hash_file=str(hash_file) if hash_file else None,
    )

    if choice == "tags":
        if fetch_limit is None or fetch_limit <= 0:
            raise typer.BadParameter("--fetch_limit must be provided and > 0 when using --tags.")
        if batch is None or batch <= 0:
            raise typer.BadParameter("--batch must be provided and > 0 when using --tags.")

        batches = make_batches(fetch_limit, batch)
        LOGGER.info(
            "[MalwareBazaar] Tags=%s | fetch_limit=%d | batch=%d | batches=%d",
            tags,
            fetch_limit,
            batch,
            len(batches),
        )
        for i, (s, e) in enumerate(batches, 1):
            LOGGER.debug("Batch %d: [%d, %d) size=%d", i, s, e, e - s)

        ingest_malwarebazaar_exec(tags=tags, fetch_limit=fetch_limit, batch=batch)

    elif choice == "hash":
        if any(v is not None for v in (fetch_limit, batch, hash_file)):
            raise typer.BadParameter(
                "--hash cannot be combined with --fetch_limit/--batch/--hash_file."
            )
        LOGGER.info("[MalwareBazaar] Single hash=%s", hash)
        ingest_malwarebazaar_exec(hash=hash)

    elif choice == "hash_file":
        if any(v is not None for v in (fetch_limit, batch, hash)):
            raise typer.BadParameter(
                "--hash_file cannot be combined with --fetch_limit/--batch/--hash."
            )
        with open(hash_file, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
        LOGGER.info("[MalwareBazaar] %d hashes loaded from %s", len(hashes), hash_file)
        ingest_malwarebazaar_exec(hash_file=hash_file)


def ingest_vxu(
    type: str = typer.Option(
        ...,
        "--type",
        help="Type of data",
        case_sensitive=False,
        click_type=click.Choice(["apt", "paper"], case_sensitive=False),
    ),
    year: Optional[int] = typer.Option(None, help="Year filter (required for type=apt)"),
    papers: bool = typer.Option(False, help="Download papers (apt mode)"),
    path: Optional[str] = typer.Option(None, help="Specific path (required for type=paper)"),
):
    """
    Ingest data from VX-Underground with strict parameter validation.

    Parameters:
        type (Literal["apt", "paper"]):
            Specifies the type of data to ingest.
            - "apt": Advanced Persistent Threat data (requires --year and --papers).
            - "paper": Research papers (requires --path).
        year (Optional[int]):
            Year filter for the data. Required for "apt" type.
        papers (bool):
            If set, downloads papers (only applicable for "apt" type).
        path (Optional[str]):
            Specific path to download papers from (required for "paper" type).

    Raises:
        typer.BadParameter:
            If required parameters are missing or invalid combinations are provided.
    """
    if type == "apt":
        if year is None:
            raise typer.BadParameter("type=apt requires --year.")
        if not papers:
            raise typer.BadParameter("type=apt requires --papers.")
        LOGGER.info("[VXU] type=apt | year=%d | papers=%s", year, papers)
        ingest_vxunderground_exec(
            type="apt",
            year=year,
            samples=False,
            papers=papers,
            batch=50,
        )

    elif type == "paper":
        if not path:
            raise typer.BadParameter("type=paper requires --path.")
        LOGGER.info("[VXU] type=paper | path=%s", path)
        ingest_vxunderground_exec(
            type="paper",
            path=path,
            papers=True,
            batch=50,
        )


def ingest_malpedia(
    page: Optional[int] = typer.Option(None, help="Page number to fetch (>= 1)"),
    search: Optional[str] = typer.Option(None, help="Keyword to search for"),
):
    """
    Ingest data from Malpedia using either a page number or a search keyword.

    This command allows you to fetch data from Malpedia in two mutually exclusive ways:
    - By specifying a page number (with --page), you can fetch a specific page of Malpedia documents.
    - By specifying a search keyword (with --search), you can search Malpedia for documents matching the keyword.


    Parameters:
        page (Optional[int]): The page number to fetch (must be >= 1). Mutually exclusive with 'search'.
        search (Optional[str]): The keyword to search for in Malpedia. Mutually exclusive with 'page'.

    Raises:
        typer.BadParameter: If neither or both of --page and --search are provided, or if the provided value is invalid.

    Usage examples:
        $ rexis ingest-malpedia --page 2
        $ rexis ingest-malpedia --search "ransomware"
    """
    choice = ensure_exactly_one("malpedia", page=page, search=search)

    if choice == "page":
        if page is None or page < 1:
            raise typer.BadParameter("--page must be >= 1.")
        LOGGER.info("[Malpedia] Fetching page=%d", page)
        # Placeholder for real ingestion:
        LOGGER.info("Would fetch Malpedia documents from page %d.", page)

    elif choice == "search":
        if not search or not search.strip():
            raise typer.BadParameter("--search must be a non-empty keyword.")
        LOGGER.info("[Malpedia] Searching for keyword='%s'", search)
        # Placeholder for real ingestion:
        LOGGER.info("Would search Malpedia for keyword '%s'.", search)
