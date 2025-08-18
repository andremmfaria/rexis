from pathlib import Path
from typing import Any
import os
import stat

import typer
from rexis.cli.utils import copy_into_samples
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
    samples_dir: Path = typer.Option(
        ...,
        "--samples-dir",
        "-s",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Directory where samples are placed/read for Ghidra",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        "-o",
        help="Overwrite if a file with the same name already exists in samples dir",
    ),
) -> None:
    """
    Decompile/analyze a binary using the Ghidra API service configured in docker-compose.

    This command copies the provided file into the mounted samples directory so it is visible
    to the Ghidra API containers, then invokes the import+analysis tool exposed by the API.

    Environment:
      - GHIDRA_API_URL: Base URL for the API gateway (default http://localhost:8000)
      - MCPO_API_KEY: API key for the service (default top-secret)
    """
    try:
        file_resolved: Path = file.resolve()
        if samples_dir in file_resolved.parents:
            dest: Path = file_resolved
        else:
            # Verify we can write into the mounted samples directory before copying
            perm_check_file = samples_dir / ".rexis_perm_check.tmp"
            def _try_write_test() -> bool:
                try:
                    with open(perm_check_file, "w") as fh:
                        fh.write("ok")
                    perm_check_file.unlink(missing_ok=True)  # type: ignore[arg-type]
                    return True
                except PermissionError:
                    return False
                except Exception:
                    # Any other failure shouldn't block the copy step—only permission matters here
                    try:
                        perm_check_file.unlink(missing_ok=True)  # type: ignore[arg-type]
                    except Exception:
                        pass
                    return True

            if not _try_write_test():
                # Attempt to add user write/execute on the directory if we own it
                try:
                    current_mode = stat.S_IMODE(os.stat(samples_dir).st_mode)
                    desired_mode = current_mode | stat.S_IWUSR | stat.S_IXUSR
                    if desired_mode != current_mode:
                        os.chmod(samples_dir, desired_mode)
                except Exception:
                    # Ignore; we'll re-test and then provide guidance if still failing
                    pass

            if not _try_write_test():
                # Still no permission: provide actionable guidance and exit
                fix_cmds = [
                    f"sudo chown -R $USER:$(id -gn) '{samples_dir}'",
                    f"sudo chmod -R u+rwX '{samples_dir}'",
                    # ACL alternative if preferred:
                    f"# or: sudo setfacl -m u:$USER:rwx '{samples_dir}'",
                ]
                tips = "\n".join(f"  {c}" for c in fix_cmds)
                raise typer.BadParameter(
                    "No permission to write into samples directory.\n"
                    f"Directory: {samples_dir}\n"
                    "Run one of the following to grant access and try again:\n"
                    f"{tips}"
                )

            dest = copy_into_samples(file_resolved, samples_dir, overwrite)
    except Exception as e:
        raise typer.BadParameter(f"Failed to prepare sample file: {e}")

    container_path: str = f"/binaries/{dest.name}"
    print(f"Invoking Ghidra import+analysis for {container_path} (from {dest})...")
    try:
        result: Any = decompile_binary_exec(container_path)
    except Exception as e:
        raise typer.Exit(code=1) from e

    # Pretty-print a concise summary; full JSON can be large, so print minimal fields if present
    # Fall back to raw print if structure unknown
    try:
        import json as _json

        print(_json.dumps(result, indent=2))
    except Exception:
        print(str(result))
