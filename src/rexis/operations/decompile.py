import httpx
from rexis.facade.pyghidra_mcp_client.api import list_project_binaries_sync_detailed
from rexis.facade.pyghidra_mcp_client.client import AuthenticatedClient
from rexis.utils.config import config
from rexis.utils.utils import LOGGER


def find_tool(name_hints=("import", "ingest", "analyz")):
    """Discover a suitable tool from the decompiler service.

    Preference order is given by name_hints occurring in id/name.
    """
    url = f"{config.decompiler.ghidra_url.rstrip("/")}/tools"
    LOGGER.info("Discovering decompiler tools at %s ...", url)
    client = AuthenticatedClient(
        base_url=config.decompiler.ghidra_url.rstrip("/"),
        token=config.decompiler.api_key,
        prefix="",  # do not add 'Bearer '
        auth_header_name="X-Api-Key",
    )
    try:
        r = client.get_httpx_client().get("/tools", timeout=30)
        r.raise_for_status()
    except httpx.HTTPError as e:
        LOGGER.error("Failed to fetch tools from %s: %s", url, e, exc_info=True)
        raise

    tools = r.json()  # [{id,name,description,params…}, …]
    LOGGER.debug(
        "Received %d tool(s) from decompiler service",
        len(tools) if isinstance(tools, list) else 0,
    )
    # Prefer import-like, then analyze-like
    ranked = sorted(
        tools,
        key=lambda t: (
            (
                0
                if any(h in t["id"].lower() or h in t.get("name", "").lower() for h in name_hints)
                else 1
            ),
            t["id"],
        ),
    )

    if not ranked:
        LOGGER.warning("No tools returned by decompiler service")
        return None

    chosen = ranked[0]
    LOGGER.info("Selected tool: %s (%s)", chosen.get("id"), chosen.get("name", ""))
    return chosen


def trigger_import_and_analysis(container_path: str):
    """Invoke the selected import/analyze tool with a best-effort payload.

    Tries multiple common parameter shapes until one succeeds (HTTP 200).
    """
    LOGGER.info("Triggering import/analyze for path: %s", container_path)
    tool = find_tool()
    if not tool:
        LOGGER.error("No import/analyze tool found via /tools")
        raise RuntimeError("No import/analyze tool found via /tools")

    # Many MCP tools accept {"path": "..."} or {"paths": ["..."]}.
    # We try common shapes; MCPO returns 422 with schema errors if wrong.
    payloads = [
        {"path": container_path},
        {"paths": [container_path]},
        {"binary_path": container_path},
        {"input_path": container_path},
    ]
    last_err = None
    client = AuthenticatedClient(
        base_url=config.decompiler.ghidra_url.rstrip("/"),
        token=config.decompiler.api_key,
        prefix="",  # do not add 'Bearer '
        auth_header_name="X-Api-Key",
    )
    for body in payloads:
        LOGGER.debug("Attempting invoke with payload keys: %s", list(body.keys()))
        try:
            r = client.get_httpx_client().post(
                f"/tools/{tool['id']}/invoke",
                json=body,
                timeout=600,
            )
            LOGGER.debug("Invoke response status: %s", r.status_code)
            if r.status_code == 200:
                LOGGER.info("Invoke succeeded for tool %s", tool.get("id"))
                result = r.json()
                try:
                    list_project_binaries_sync_detailed(client=client)
                    LOGGER.debug("Ghidra client smoke test: list_project_binaries ok")
                except Exception as e:
                    LOGGER.debug("Ghidra client smoke test skipped/failed: %s", e)
                return result
            last_err = f"{r.status_code} {r.text[:200]}"
        except httpx.HTTPError as e:
            LOGGER.warning("Invoke attempt failed: %s", e)
            last_err = str(e)

    LOGGER.error("Invoke failed for tool %s: %s", tool.get("id"), last_err)
    raise RuntimeError(f"Invoke failed for tool {tool['id']}: {last_err}")
