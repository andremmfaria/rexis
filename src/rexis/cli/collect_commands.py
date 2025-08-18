import time
import uuid
from pathlib import Path
from typing import Optional

import typer
from rexis.tools.documents import collect_documents_exec
from rexis.operations.collect.malpedia import collect_malpedia_exec
from rexis.operations.collect.malwarebazaar import collect_malwarebazaar_exec
from rexis.operations.ingest.main import ingest_file_exec


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
    run_name: Optional[str] = typer.Option(
        None, "--run-name", "-n", help="Run name (used to name the output files and folder)"
    ),
    output_dir: Path = typer.Option(
        Path("."), "--output-dir", "-o", help="Directory to write outputs into"
    ),
    ingest: bool = typer.Option(False, "--ingest", "-i", help="Ingest the collected data"),
) -> None:
    """
    Collects malware data from Malpedia and optionally ingests the collected files.

    This function serves as the entrypoint for the Typer CLI command to collect malware samples and metadata from Malpedia,
    filtering by family ID, actor ID, search term, and date range. The results are saved to a JSON file in the specified
    output directory. Optionally, the collected files can be ingested for further processing.

    Parameters:
        family_id (Optional[str]): Malpedia family ID (e.g., "win.cobalt_strike").
        actor_id (Optional[str]): Malpedia actor ID (e.g., "apt.turla").
        search_term (Optional[str]): Search term to filter results (e.g., "CobaltStrike").
        start_date (Optional[str]): Start date filter in YYYY-MM-DD format.
        end_date (Optional[str]): End date filter in YYYY-MM-DD format.
        max_items (Optional[int]): Maximum number of items to keep after filtering.
        run_name (Optional[str]): Name for the run, used to name output files and folders.
        output_dir (Path): Directory to write output files into.
        ingest (bool): If True, ingests the collected data after saving.

    Raises:
        typer.BadParameter: If invalid parameters are provided.
        Exception: If an error occurs during ingestion.

    Outputs:
        - Saves collected data as a JSON file in the output directory.
        - Optionally ingests collected files and prints progress information.
    """
    try:
        if not run_name:
            run_name = uuid.uuid4().hex
        base = f"{run_name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path: Path = output_dir / f"{base}.json"
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
    run_dir = output_dir / base
    print(f"Saved {num_saved} JSON objects to {output_path} and scrapes will be in {run_dir}")

    try:
        if ingest:
            results = collect_documents_exec(
                input_path=output_path, metadata={"source": "malpedia"}
            )
            total = len(results)
            ingested = 0
            processed = 0
            for item in results:
                file_type = item.get("file_type")
                file_path = item.get("file_path")
                meta = item.get("metadata") or {"source": "malpedia"}
                if not file_type or not file_path:
                    processed += 1
                    print(f"Ingest progress: {processed}/{total}")
                    continue
                # Ingest each file individually
                ingest_file_exec(
                    ftype=file_type,
                    target_file=Path(file_path),
                    metadata=meta,
                )
                ingested += 1
                processed += 1
                print(f"Ingest progress: {processed}/{total}")
            print(f"Ingested {ingested} items from {run_dir}")
    except Exception as e:
        print(f"Error ingesting data: {e}")


def collect_malwarebazaar(
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Tags to search for"),
    fetch_limit: Optional[int] = typer.Option(
        None, "--fetch-limit", "-l", help="How many entries to fetch per tag", min=1
    ),
    batch: Optional[int] = typer.Option(
        10, "--batch", "-b", help="Batch size for ingestion (also required with --tags)", min=1
    ),
    hash: Optional[str] = typer.Option(None, "--hash", "-s", help="Single SHA256 hash to fetch"),
    hash_file: Optional[Path] = typer.Option(
        None,
        "--hash-file",
        "-F",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="File with newline-separated hashes",
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", "-n", help="Run name (if not present a UUID will be created)"
    ),
    output_dir: Path = typer.Option(
        Path("."), "--output-dir", "-o", help="Directory to write outputs into"
    ),
    ingest: bool = typer.Option(False, "--ingest", "-i", help="Ingest the collected API data"),
) -> None:
    """
    Collect raw MalwareBazaar JSON data and optionally ingest it into the index.

    This function serves as the entrypoint for the Typer CLI interface to interact with the MalwareBazaar API.
    It allows users to fetch malware sample metadata based on tags, SHA256 hashes, or a file containing hashes.
    The collected data is saved as a JSON file, and can optionally be ingested into the index for further processing.

    Parameters:
        tags (Optional[str]): Tags to search for in MalwareBazaar. Multiple tags can be specified.
        fetch_limit (Optional[int]): Maximum number of entries to fetch per tag.
        batch (Optional[int]): Batch size for ingestion. Required when using tags.
        hash (Optional[str]): Single SHA256 hash to fetch from MalwareBazaar.
        hash_file (Optional[Path]): Path to a file containing newline-separated SHA256 hashes.
        run_name (Optional[str]): Name for the run. If not provided, a UUID will be generated.
        output_dir (Path): Directory to write the output JSON file. Defaults to the current directory.
        ingest (bool): If True, ingests the collected JSON data into the index.

    Raises:
        typer.BadParameter: If invalid parameters are provided.
        Exception: If an error occurs during ingestion.

    Side Effects:
        - Writes collected JSON data to the specified output directory.
        - Optionally ingests the collected data into the index.
    """
    try:
        if not run_name:
            run_name = uuid.uuid4().hex
        base = f"{run_name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path: Path = output_dir / f"{base}.json"

        num_saved: int = collect_malwarebazaar_exec(
            tags=tags,
            fetch_limit=fetch_limit,
            batch=batch,
            hash=hash,
            hash_file=hash_file,
            output_path=output_path,
        )
    except ValueError as error:
        raise typer.BadParameter(str(error))

    print(f"Saved {num_saved} JSON objects to {output_path}")

    try:
        if ingest and num_saved > 0:
            print("Ingesting MalwareBazaar JSON via ingest_file_exec...")
            ingest_file_exec(
                ftype="json", target_file=output_path, metadata={"source": "malwarebazaar"}
            )
            print(f"Ingested MalwareBazaar JSON from {output_path}")
    except Exception as e:
        print(f"Error ingesting MalwareBazaar data: {e}")
