import time
from typing import List

import pyfiglet
import typer
from haystack.dataclasses import Document
from rexis.operations.analyse import analyse
from rexis.operations.populate_db import fetch_malware_documents, index_documents
from rexis.utils.utils import LOGGER, get_version, setup_logging
from rich import print as rich_print

app = typer.Typer(
    help="🚀 REXIS Static Malware Analysis CLI",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)


# --- Command: populate_db ---
@app.command()
def populate_db(
    tags: list[str] = typer.Option(..., "-t", "--tags", help="List of tags to fetch samples for.")
):
    """
    Populate the database with malware documents based on tags.

    Example:
    rexis populate-db --tags ransomware trojan banker
    """
    ingest_data_into_db(tag_list=tags)


# --- Command: prompt (analyze) ---
@app.command()
def prompt(query: str = typer.Option(..., "-q", "--query", help="Query string to analyze.")):
    """
    Analyze malware behaviour using your indexed database and GPT-4o.

    Example:
    rexis prompt --query "How does Emotet persist?"
    """
    analyze_prompt(query=query)


# --- Global Callback ---
@app.callback(invoke_without_command=True)
def entrypoint(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug output."),
    version: bool = typer.Option(
        False, "--version", "-V", help="Shows the version of REXIS.", is_eager=True
    ),
):
    """
    Entry point for REXIS CLI application.
    """
    if version:
        rich_print(
            f"[bold magenta] REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold magenta]"
        )
        raise typer.Exit()

    rich_print(f"[bold cyan]{pyfiglet.figlet_format('REXIS')}[/bold cyan]")
    rich_print(f"[bold cyan]REXIS Static Malware Analysis CLI v{get_version()} 🚀 [/bold cyan]")
    setup_logging(verbose=verbose)


def main():
    """
    Main function to run the REXIS CLI application.

    This function serves as the entry point for the REXIS CLI application.
    It initializes the application and sets up logging based on user input.

    Returns:
        None
    """
    app()


def ingest_data_into_db(tag_list: List[str] = None) -> None:
    """
    Populate the database with malware documents based on the provided tags.

    This function fetches malware documents for each tag in the provided
    `tag_list` by querying an external source. The fetched documents are
    then indexed into the database. The function also logs the time taken
    to fetch documents for each tag.

    Args:
        tag_list (List[str], optional): A list of tags to query malware
            documents. Defaults to None.

    Returns:
        None: This function does not return any value.

    Side Effects:
        - Fetches malware documents for each tag in `tag_list`.
        - Indexes the fetched documents into the database.
        - Prints the time taken for each tag and the total number of
          indexed documents.
        - Introduces a 1-second delay between processing each tag.
    """
    sample_docs: List[Document] = []
    for tag in tag_list:
        LOGGER.info(f"Fetching documents for tag: {tag}")
        start_time = time.time()
        try:
            documents = fetch_malware_documents(
                query_type="tag",
                query_value=tag,
            )
            sample_docs.extend(documents)
            elapsed_time = time.time() - start_time
            LOGGER.info(
                f"Fetched {len(documents)} documents for tag '{tag}' in {elapsed_time:.2f} seconds."
            )
        except Exception as e:
            LOGGER.error(f"Error fetching documents for tag '{tag}': {e}")
        time.sleep(1)

    if sample_docs:
        try:
            LOGGER.info("Indexing fetched documents into the database.")
            index_documents(sample_docs)
            LOGGER.info(f"Successfully indexed {len(sample_docs)} documents.")
        except Exception as e:
            LOGGER.error(f"Error indexing documents: {e}")
    else:
        LOGGER.warning("No documents fetched. Skipping indexing.")


def analyze_prompt(query: str) -> None:
    """
    Analyzes the given query by passing it to the `analyse` function.

    Args:
        query (str): The input string to be analyzed.

    Returns:
        None
    """
    response = analyse(query=query)
    rich_print(f"[bold green]Response:[/bold green] {response}")
    LOGGER.info(f"Analysis completed for query: {query}")


if __name__ == "__main__":
    main()
