from typing import List, Optional

import pyfiglet
import typer

# from rexis.operations.analyse import analyse_baseline, analyse_llm_rag
from rexis.operations.ingest import ingest_exec
from rexis.utils.utils import LOGGER, get_version, setup_logging
from rich import print as rich_print

app = typer.Typer(
    help="🚀 REXIS Static Malware Analysis CLI",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)


# --- Command: ingest ---
@app.command("ingest")
def ingest_data(
    hash: str = typer.Option(None, "--hash", help="SHA-256 hash of a specific sample."),
    tags: Optional[str] = typer.Option(
        None,
        "--tags",
        "-t",
        help="Comma separated list of tags to query samples by. e.g., ransomware,trojan.",
    ),
    limit: int = typer.Option(100, "--limit", "-l", help="Max number of samples per tag."),
    file: str = typer.Option(
        None, "--file", "-f", help="Path to a file with one SHA-256 hash per line."
    ),
    source: str = typer.Option(
        "all", "--source", "-s", help="Source to use: malwarebazaar, virustotal, or all."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Force re-ingestion even if sample exists in DB."
    ),
):
    """
    Ingest malware samples and intelligence into the vector database.

    Examples:
    - rexis ingest --hash <hash>
    - rexis ingest --tags ransomware,trojan --limit 50 --source malwarebazaar
    - rexis ingest --file hashes.txt
    """
    # Enforce exclusivity: hash > file > tags
    exclusive_params = [bool(hash), bool(file), bool(tags)]
    if sum(exclusive_params) > 1:
        rich_print("[bold red]Error:[/bold red] Only one of --hash, --file, or --tags can be specified at a time.")
        raise typer.Exit(code=1)

    ingest_exec(
        hash=hash,
        tags=[t.strip() for t in tags.split(",")] if tags else None,
        file_path=file,
        source=source,
        refresh=refresh,
        limit=limit,
    )


# # --- Command: baseline ---
# @app.command("baseline")
# def baseline_pipeline(
#     sha256: str = typer.Option(..., "--sha256", help="SHA-256 hash of the malware sample."),
# ):
#     """
#     Run the static baseline pipeline for the given SHA256 sample.

#     Example:
#     rexis baseline --sha256 abc123...
#     """
#     result = analyse_baseline(sha256=sha256)
#     rich_print(f"[bold blue]Baseline Result:[/bold blue] {result}")


# # --- Command: llmrag ---
# @app.command("llmrag")
# def llmrag_pipeline(
#     sha256: str = typer.Option(..., "--sha256", help="SHA-256 hash of the malware sample."),
#     top_k: int = typer.Option(5, "--top-k", help="Number of documents to retrieve."),
#     temperature: float = typer.Option(0.2, "--temperature", help="LLM response randomness."),
#     model: str = typer.Option(
#         "gpt-4o", "--model", help="LLM model to use (e.g., gpt-4o or deepseek-r1)."
#     ),
# ):
#     """
#     Run the LLM+RAG pipeline for the given SHA256 sample.

#     Example:
#     rexis llmrag --sha256 abc123... --top-k 5 --temperature 0.3 --model gpt-4o
#     """
#     response = analyse_llm_rag(
#         sha256=sha256,
#         top_k=top_k,
#         temperature=temperature,
#         model=model,
#     )
#     rich_print(f"[bold magenta]LLM+RAG Result:[/bold magenta] {response}")


# --- Global Callback ---
@app.callback(invoke_without_command=True)
def entrypoint(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug output."),
    version: bool = typer.Option(
        False, "--version", "-V", help="Show REXIS version and exit.", is_eager=True
    ),
):
    """
    REXIS CLI entry point.
    """
    if version:
        rich_print(f"[bold magenta] REXIS CLI v{get_version()} 🚀 [/bold magenta]")
        raise typer.Exit()

    rich_print(f"[bold cyan]{pyfiglet.figlet_format('REXIS')}[/bold cyan]")
    rich_print(f"[bold cyan]REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold cyan]")
    setup_logging(verbose=verbose)


def main():
    app()


if __name__ == "__main__":
    main()
