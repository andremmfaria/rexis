import uuid
from pathlib import Path
from typing import List, Optional

import typer
from rexis.cli.utils import parse_metadata_list, validate_dir_or_file, validate_file_type
from rexis.operations.ingest.main import ingest_file_exec


def ingest_file(
    type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="File type to ingest: pdf, html, json, or text",
        show_choices=True,
        case_sensitive=False,
        callback=validate_file_type,
    ),
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single file to ingest",
    ),
    batch: int = typer.Option(
        5, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all ingestion artifacts and reports (defaults to CWD)",
    ),
    run_name: Optional[str] = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this ingestion run. Defaults to a UUID if omitted.",
    ),
) -> None:
    """
    Ingest a file or directory of files into the index.

    This is the generic Typer CLI entrypoint for ingesting different file types. You must
    provide exactly one of --dir or --file. The --type option determines how content is
    parsed (pdf, html, json, or text) and is validated before execution.

    Parameters:
        type (str): File type to ingest. One of {"pdf", "html", "json", "text"}.
        dir (Optional[Path]): Directory containing files to ingest (batch mode).
        file (Optional[Path]): Single file to ingest.
        batch (int): Batch size used when ingesting a directory.
        metadata (Optional[List[str]]): Arbitrary metadata as key=value pairs. Can be
            provided multiple times and will be parsed into a dict.

    Raises:
        typer.BadParameter: If --type is invalid, metadata pairs are malformed, or not
            exactly one of --dir/--file is provided.

    Side Effects:
        - Prints a summary of the ingestion request.
        - Executes the ingestion via ingest_file_exec.
    """
    validate_dir_or_file(dir, file)
    metadata_dict = parse_metadata_list(metadata)
    print(
        f"[FILE] type={type} | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )

    run_name_str = run_name or uuid.uuid4().hex
    report_path = ingest_file_exec(
        ftype=type,
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
        out_dir=out_dir,
        run_name=run_name_str,
    )
    typer.echo(f"[ingest] Run report: {report_path}")


def ingest_file_pdf(
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of PDF files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single PDF file to ingest",
    ),
    batch: int = typer.Option(
        5, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all ingestion artifacts and reports (defaults to CWD)",
    ),
    run_name: Optional[str] = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this ingestion run. Defaults to a UUID if omitted.",
    ),
) -> None:
    """
    Ingest PDF content from a single file or a directory of files.

    This Typer CLI entrypoint is a typed convenience wrapper over ingest_file for PDFs.
    Provide exactly one of --dir or --file.

    Parameters:
        dir (Optional[Path]): Directory with PDF files to ingest (batch mode).
        file (Optional[Path]): Single PDF file to ingest.
        batch (int): Batch size used when ingesting a directory.
        metadata (Optional[List[str]]): Arbitrary metadata as key=value pairs (repeatable).

    Raises:
        typer.BadParameter: If metadata pairs are malformed or not exactly one of
            --dir/--file is provided.

    Side Effects:
        - Prints a summary of the ingestion request.
        - Executes the ingestion via ingest_file_exec with ftype="pdf".
    """
    validate_dir_or_file(dir, file)
    metadata_dict = parse_metadata_list(metadata)
    print(
        f"[FILE] type=pdf | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    run_name_str = run_name or uuid.uuid4().hex
    report_path = ingest_file_exec(
        ftype="pdf",
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
        out_dir=out_dir,
        run_name=run_name_str,
    )
    typer.echo(f"[ingest] Run report: {report_path}")


def ingest_file_html(
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of HTML files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single HTML file to ingest",
    ),
    batch: int = typer.Option(
        5, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all ingestion artifacts and reports (defaults to CWD)",
    ),
    run_name: Optional[str] = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this ingestion run. Defaults to a UUID if omitted.",
    ),
) -> None:
    """
    Ingest HTML content from a single file or a directory of files.

    This Typer CLI entrypoint is a typed convenience wrapper over ingest_file for HTML.
    Provide exactly one of --dir or --file.

    Parameters:
        dir (Optional[Path]): Directory with HTML files to ingest (batch mode).
        file (Optional[Path]): Single HTML file to ingest.
        batch (int): Batch size used when ingesting a directory.
        metadata (Optional[List[str]]): Arbitrary metadata as key=value pairs (repeatable).

    Raises:
        typer.BadParameter: If metadata pairs are malformed or not exactly one of
            --dir/--file is provided.

    Side Effects:
        - Prints a summary of the ingestion request.
        - Executes the ingestion via ingest_file_exec with ftype="html".
    """
    validate_dir_or_file(dir, file)
    metadata_dict = parse_metadata_list(metadata)
    print(
        f"[FILE] type=html | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    run_name_str = run_name or uuid.uuid4().hex
    report_path = ingest_file_exec(
        ftype="html",
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
        out_dir=out_dir,
        run_name=run_name_str,
    )
    typer.echo(f"[ingest] Run report: {report_path}")


def ingest_file_text(
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of TEXT files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single TEXT file to ingest",
    ),
    batch: int = typer.Option(
        5, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all ingestion artifacts and reports (defaults to CWD)",
    ),
    run_name: Optional[str] = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this ingestion run. Defaults to a UUID if omitted.",
    ),
) -> None:
    """
    Ingest plain text content from a single file or a directory of files.

    This Typer CLI entrypoint is a typed convenience wrapper over ingest_file for text.
    Provide exactly one of --dir or --file.

    Parameters:
        dir (Optional[Path]): Directory with text files to ingest (batch mode).
        file (Optional[Path]): Single text file to ingest.
        batch (int): Batch size used when ingesting a directory.
        metadata (Optional[List[str]]): Arbitrary metadata as key=value pairs (repeatable).

    Raises:
        typer.BadParameter: If metadata pairs are malformed or not exactly one of
            --dir/--file is provided.

    Side Effects:
        - Prints a summary of the ingestion request.
        - Executes the ingestion via ingest_file_exec with ftype="text".
    """
    validate_dir_or_file(dir, file)
    metadata_dict = parse_metadata_list(metadata)
    print(
        f"[FILE] type=text | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    run_name_str = run_name or uuid.uuid4().hex
    report_path = ingest_file_exec(
        ftype="text",
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
        out_dir=out_dir,
        run_name=run_name_str,
    )
    typer.echo(f"[ingest] Run report: {report_path}")


def ingest_file_json(
    dir: Optional[Path] = typer.Option(
        None,
        "--dir",
        "-d",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory of JSON files to ingest (batch mode)",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Single JSON file to ingest",
    ),
    batch: int = typer.Option(
        5, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
    out_dir: Path = typer.Option(
        Path.cwd(),
        "--out-dir",
        "-o",
        help="Directory for all ingestion artifacts and reports (defaults to CWD)",
    ),
    run_name: Optional[str] = typer.Option(
        None,
        "--run-name",
        "-r",
        help="Optional logical name to tag this ingestion run. Defaults to a UUID if omitted.",
    ),
) -> None:
    """
    Ingest JSON content from a single file or a directory of files.

    This Typer CLI entrypoint is a typed convenience wrapper over ingest_file for JSON.
    Provide exactly one of --dir or --file.

    Parameters:
        dir (Optional[Path]): Directory with JSON files to ingest (batch mode).
        file (Optional[Path]): Single JSON file to ingest.
        batch (int): Batch size used when ingesting a directory.
        metadata (Optional[List[str]]): Arbitrary metadata as key=value pairs (repeatable).

    Raises:
        typer.BadParameter: If metadata pairs are malformed or not exactly one of
            --dir/--file is provided.

    Side Effects:
        - Prints a summary of the ingestion request.
        - Executes the ingestion via ingest_file_exec with ftype="json".
    """
    validate_dir_or_file(dir, file)
    metadata_dict = parse_metadata_list(metadata)
    print(
        f"[FILE] type=json | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    run_name_str = run_name or uuid.uuid4().hex
    report_path = ingest_file_exec(
        ftype="json",
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
        out_dir=out_dir,
        run_name=run_name_str,
    )
    typer.echo(f"[ingest] Run report: {report_path}")
