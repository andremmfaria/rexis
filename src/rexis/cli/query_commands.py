import rich
import typer
from rexis.utils.utils import LOGGER


def baseline_query(
    sha256: str = typer.Option(..., "--sha256", help="SHA-256 hash of the malware sample."),
):
    """
    Run the static baseline pipeline for the given SHA256 sample.

    Example:
    rexis baseline --sha256 abc123...
    """
    result = analyse_baseline(sha256=sha256)
    rich.print(f"[bold blue]Baseline Result:[/bold blue] {result}")


def llmrag_query(
    sha256: str = typer.Option(..., "--sha256", help="SHA-256 hash of the malware sample."),
    top_k: int = typer.Option(5, "--top-k", help="Number of documents to retrieve."),
    temperature: float = typer.Option(0.2, "--temperature", help="LLM response randomness."),
    model: str = typer.Option(
        "gpt-4o", "--model", help="LLM model to use (e.g., gpt-4o or deepseek-r1)."
    ),
):
    """
    Run the LLM+RAG pipeline for the given SHA256 sample.

    Example:
    rexis llmrag --sha256 abc123... --top-k 5 --temperature 0.3 --model gpt-4o
    """
    response = analyse_llm_rag(
        sha256=sha256,
        top_k=top_k,
        temperature=temperature,
        model=model,
    )
    rich.print(f"[bold magenta]LLM+RAG Result:[/bold magenta] {response}")
