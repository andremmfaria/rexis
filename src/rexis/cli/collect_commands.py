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
    output_path: Path = typer.Option(
        Path("malpedia_urls.json"), "--output-path", "-o", help="Output file path"
    ),
    ingest: bool = typer.Option(False, "--ingest", "-i", help="Ingest the collected data"),
) -> None:
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

    try:
        if ingest:
            results = collect_documents_exec(
                input_path=output_path, metadata={"source": "malpedia"}
            )
            ingested = 0
            for item in results:
                file_type = item.get("file_type")
                file_path = item.get("file_path")
                meta = item.get("metadata") or {"source": "malpedia"}
                if not file_type or not file_path:
                    continue
                # Ingest each file individually
                ingest_file_exec(
                    ftype=file_type,
                    target_file=Path(file_path),
                    metadata=meta,
                )
                ingested += 1
            typer.echo(f"Ingested {ingested} items from {output_path}")
    except Exception as e:
        typer.echo(f"Error ingesting data: {e}")
