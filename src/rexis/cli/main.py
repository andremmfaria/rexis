import pyfiglet
import rich
import typer
from rexis.cli.collect_commands import collect_malpedia
from rexis.cli.ingestion_commands import ingest_api, ingest_file
from rexis.cli.query_commands import baseline_query, llmrag_query
from rexis.utils.utils import get_version, setup_logging

cli_app = typer.Typer(
    help="🚀 REXIS Static Malware Analysis CLI",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)

collect_app = typer.Typer(help="Data collection commands")
cli_app.add_typer(collect_app, name="collect")

collect_app.command("malpedia")(collect_malpedia)


ingest_app = typer.Typer(help="Data ingestion commands")
cli_app.add_typer(ingest_app, name="ingest")

ingest_app.command("api")(ingest_api)
ingest_app.command("file")(ingest_file)


query_app = typer.Typer(help="Data query commands")
cli_app.add_typer(query_app, name="query")

query_app.command("baseline")(baseline_query)
query_app.command("llmrag")(llmrag_query)


# --- Global Callback ---
@cli_app.callback(invoke_without_command=True)
def entrypoint(
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Increase verbosity (-v for info, -vv for debug).",
    ),
    version: bool = typer.Option(
        False, "--version", "-V", help="Show REXIS version and exit.", is_eager=True
    ),
):
    """
    REXIS CLI entry point.
    """
    if version:
        rich.print(f"[bold magenta] REXIS CLI v{get_version()} 🚀 [/bold magenta]")
        raise typer.Exit()

    rich.print(f"[bold cyan]{pyfiglet.figlet_format('REXIS')}[/bold cyan]")
    rich.print(f"[bold cyan]REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold cyan]")
    setup_logging(verbosity=verbose)
