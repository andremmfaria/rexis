import pyfiglet
import typer
import rich

from rexis.utils.utils import get_version, setup_logging

import typer

from rexis.cli.ingestion_commands import ingest_malwarebazaar, ingest_malpedia, ingest_vxu
from rexis.cli.query_commands import baseline_query, llmrag_query

cli_app = typer.Typer(
    help="🚀 REXIS Static Malware Analysis CLI",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)

ingest_app = typer.Typer(help="Data ingestion commands")
cli_app.add_typer(ingest_app, name="ingest")

# Register ingestion commands
ingest_app.command("malwarebazaar")(ingest_malwarebazaar)
ingest_app.command("malpedia")(ingest_malpedia)
ingest_app.command("vxu")(ingest_vxu)

query_app = typer.Typer(help="Data query commands")
cli_app.add_typer(query_app, name="query")

# Register query commands
query_app.command("baseline")(baseline_query)
query_app.command("llmrag")(llmrag_query)


# --- Global Callback ---
@cli_app.callback(invoke_without_command=True)
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
        rich.print(f"[bold magenta] REXIS CLI v{get_version()} 🚀 [/bold magenta]")
        raise typer.Exit()

    rich.print(f"[bold cyan]{pyfiglet.figlet_format('REXIS')}[/bold cyan]")
    rich.print(f"[bold cyan]REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold cyan]")
    setup_logging(verbose=verbose)
