from pathlib import Path
from typing import Optional

import typer
from rexis.operations.decompile import decompile_binary_exec


def decompile_binary(
    file: Path = typer.Option(
        ...,
        "--file",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Path to the binary to decompile",
    ),
    out_dir: Path = typer.Option(
        ...,
        "--out-dir",
        "-o",
        "-s",
        exists=False,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Directory where the decompiled output will be saved",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        "-y",
        help="Overwrite if a file with the same name already exists in output dir",
    ),
    project_dir: Optional[Path] = typer.Option(
        None,
        "--project-dir",
        "-p",
        help="Directory for the local Ghidra project store (cached analysis). Defaults to ~/.rexis/ghidra_projects.",
    ),
    project_name: str = typer.Option(
        "rexis",
        "--project-name",
        "-n",
        help="Ghidra project name to reuse between runs.",
    ),
) -> None:
    try:
        out_path = decompile_binary_exec(
            file=file,
            out_dir=out_dir,
            overwrite=overwrite,
            project_dir=project_dir,
            project_name=project_name,
        )
        typer.echo(f"Wrote {out_path}")
    except FileExistsError as e:
        raise typer.BadParameter(str(e))
    except FileNotFoundError as e:
        raise typer.BadParameter(str(e))
    except RuntimeError as e:
        # Likely GHIDRA env issue
        raise typer.BadParameter(str(e))
