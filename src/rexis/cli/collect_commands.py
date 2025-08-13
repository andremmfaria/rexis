import time
import uuid
from pathlib import Path
from typing import Optional

import typer
from rexis.operations.collect.documents import collect_documents_exec
from rexis.operations.collect.malpedia import collect_malpedia_exec
from rexis.operations.ingest.ingest_file import ingest_file_exec


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
    try:
        if not run_name: run_name = uuid.uuid4().hex
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
    print(
        f"Saved {num_saved} JSON objects to {output_path} and scrapes will be in {run_dir}"
    )

    try:
        if ingest:
            results = collect_documents_exec(input_path=output_path, metadata={"source": "malpedia"})
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
