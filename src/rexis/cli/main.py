import pyfiglet
import rich
import typer
from rexis.cli.collect_commands import collect_malpedia, collect_malwarebazaar
from rexis.cli.decompile_commands import decompile_binary
from rexis.cli.ingestion_commands import (
    ingest_file,
    ingest_file_html,
    ingest_file_json,
    ingest_file_pdf,
    ingest_file_text,
)
from rexis.cli.analyse_commands import cmd_analyze_baseline
from rexis.utils.utils import get_version, setup_logging

cli_app = typer.Typer(
    help="🚀 REXIS Static Malware Analysis CLI",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)

collect_app = typer.Typer(help="Data collection commands")
cli_app.add_typer(collect_app, name="collect")

collect_app.command("malpedia")(collect_malpedia)
collect_app.command("malwarebazaar")(collect_malwarebazaar)


ingest_app = typer.Typer(help="Data ingestion commands")
cli_app.add_typer(ingest_app, name="ingest")

ingest_app.command("file")(ingest_file)
ingest_app.command("pdf")(ingest_file_pdf)
ingest_app.command("html")(ingest_file_html)
ingest_app.command("text")(ingest_file_text)
ingest_app.command("json")(ingest_file_json)


query_app = typer.Typer(help="Data analysis commands")
cli_app.add_typer(query_app, name="analyse")

query_app.command("baseline")(cmd_analyze_baseline)
# query_app.command("llmrag")(llmrag_query)


# Decompile/analysis commands
cli_app.command("decompile")(decompile_binary)


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
) -> None:
    """
    REXIS CLI entry point.
    """
    if version:
        rich.print(f"[bold magenta] REXIS CLI v{get_version()} 🚀 [/bold magenta]")
        raise typer.Exit()

    rich.print(f"[bold cyan]{pyfiglet.figlet_format('REXIS')}[/bold cyan]")
    rich.print(f"[bold cyan]REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold cyan]")
    setup_logging(verbosity=verbose)
