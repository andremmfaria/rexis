import json

import requests
from rexis.utils.config import config
from rexis.utils.utils import LOGGER

# Base URL and headers for the decompiler service (do not log secrets)
BASE = config.decompiler.ghidra_url.rstrip("/")
HEADERS = {"X-Api-Key": config.decompiler.api_key}


def find_tool(name_hints=("import", "ingest", "analyz")):
    """Discover a suitable tool from the decompiler service.

    Preference order is given by name_hints occurring in id/name.
    """
    url = f"{BASE}/tools"
    LOGGER.info("Discovering decompiler tools at %s ...", url)
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
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
    print("Triggering import/analyze for path: %s", container_path)
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
    for body in payloads:
        LOGGER.debug("Attempting invoke with payload keys: %s", list(body.keys()))
        try:
            r = requests.post(
                f"{BASE}/tools/{tool['id']}/invoke",
                headers={**HEADERS, "Content-Type": "application/json"},
                data=json.dumps(body),
                timeout=600,
            )
            LOGGER.debug("Invoke response status: %s", r.status_code)
            if r.status_code == 200:
                print("Invoke succeeded for tool %s", tool.get("id"))
                return r.json()
            last_err = f"{r.status_code} {r.text[:200]}"
        except Exception as e:
            LOGGER.warning("Invoke attempt failed: %s", e)
            last_err = str(e)

    LOGGER.error("Invoke failed for tool %s: %s", tool.get("id"), last_err)
    raise RuntimeError(f"Invoke failed for tool {tool['id']}: {last_err}")
