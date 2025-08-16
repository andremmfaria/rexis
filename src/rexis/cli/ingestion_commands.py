from pathlib import Path
from typing import List, Optional

import typer
from rexis.cli.utils import _parse_metadata_list, _validate_dir_or_file, _validate_file_type
from rexis.operations.ingest.main import ingest_file_exec
from rexis.utils.utils import LOGGER


def ingest_file(
    type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="File type to ingest: pdf, html, json, or text",
        show_choices=True,
        case_sensitive=False,
        callback=_validate_file_type,
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
        10, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    _validate_dir_or_file(dir, file)
    metadata_dict = _parse_metadata_list(metadata)
    print(
        f"[FILE] type={type} | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )

    ingest_file_exec(
        ftype=type,
        target_dir=dir,
        target_file=file,
        batch=batch,
        metadata=metadata_dict,
    )


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
        10, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    _validate_dir_or_file(dir, file)
    metadata_dict = _parse_metadata_list(metadata)
    print(
        f"[FILE] type=pdf | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    ingest_file_exec(
        ftype="pdf", target_dir=dir, target_file=file, batch=batch, metadata=metadata_dict
    )


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
        10, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    _validate_dir_or_file(dir, file)
    metadata_dict = _parse_metadata_list(metadata)
    print(
        f"[FILE] type=html | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    ingest_file_exec(
        ftype="html", target_dir=dir, target_file=file, batch=batch, metadata=metadata_dict
    )


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
        10, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    _validate_dir_or_file(dir, file)
    metadata_dict = _parse_metadata_list(metadata)
    print(
        f"[FILE] type=text | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    ingest_file_exec(
        ftype="text", target_dir=dir, target_file=file, batch=batch, metadata=metadata_dict
    )


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
        10, "--batch", "-b", min=1, help="Batch size for indexing (when using --dir)"
    ),
    metadata: Optional[List[str]] = typer.Option(
        None,
        "--metadata",
        "-m",
        help="Arbitrary metadata as key=value pairs. Can be used multiple times.",
    ),
) -> None:
    _validate_dir_or_file(dir, file)
    metadata_dict = _parse_metadata_list(metadata)
    print(
        f"[FILE] type=json | mode={'dir' if dir else 'file'} | batch={batch} | metadata={metadata_dict}"
    )
    ingest_file_exec(
        ftype="json", target_dir=dir, target_file=file, batch=batch, metadata=metadata_dict
    )
