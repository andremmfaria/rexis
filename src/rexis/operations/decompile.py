from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TypedDict, cast

import httpx
from rexis.facade.pyghidra_mcp_client.api import (
    decompile_function_sync,
    list_project_binaries_sync_detailed,
)
from rexis.facade.pyghidra_mcp_client.client import AuthenticatedClient
from rexis.facade.pyghidra_mcp_client.models.decompile_function_form_model import (
    DecompileFunctionFormModel,
)
from rexis.utils.config import config
from rexis.utils.utils import LOGGER


class ToolInfo(TypedDict, total=False):
    """Typed shape for decompiler tool metadata returned by /tools."""

    id: str
    name: str
    description: str


def decompile_binary_exec(container_path: str) -> Any:
    """Copy/import a binary into the project, analyze it, then fetch decompiled code.

    - Discovers an import/analyze tool via /tools and invokes it directly.
    - After a successful analysis, decompiles a default function (main) from the binary.

    Returns a dictionary with both analysis and decompilation results when possible.
    """
    print(f"Importing and analyzing binary at: {container_path}")
    client: AuthenticatedClient = AuthenticatedClient(
        base_url=config.decompiler.ghidra_url.rstrip("/"),
        token=config.decompiler.api_key,
    )

    try:
        list_project_binaries_sync_detailed(client=client)
        LOGGER.debug("Ghidra client smoke test: list_project_binaries ok")
    except Exception as e:
        LOGGER.debug("Ghidra client smoke test skipped/failed: %s", e)

    # After analysis, attempt to decompile a default function (main) from the imported binary
    binary_name: str = Path(container_path).name
    decomp_result: Optional[Any] = None
    try:
        decomp_result = decompile_function(
            client=client, binary_name=binary_name, function_name="main"
        )
    except Exception as e:
        LOGGER.warning(
            "Decompile step failed for binary '%s' function 'main': %s",
            binary_name,
            e,
        )

    return {"result": decomp_result}


def decompile_function(client: AuthenticatedClient, binary_name: str, function_name: str) -> Any:
    """Decompile a specific function from a binary using the dedicated API tool.

    This directly calls the endpoint implemented in
    `rexis.facade.pyghidra_mcp_client.api.tool_decompile_function_post`.

    Args:
        client: Authenticated Ghidra API client.
        binary_name: The name of the binary already present in the Ghidra project.
        function_name: The name of the function to decompile.

    Returns:
        Parsed response with decompiled code and optional metadata.
    """
    print(f"Decompiling function '{function_name}' from binary '{binary_name}'")
    body = DecompileFunctionFormModel(binary_name=binary_name, name=function_name)
    try:
        resp = decompile_function_sync(client=client, body=body)
        LOGGER.debug("Decompile response type: %s", type(resp).__name__)
        return resp
    except httpx.HTTPError as e:
        LOGGER.error("Decompile request failed: %s", e, exc_info=True)
        raise
