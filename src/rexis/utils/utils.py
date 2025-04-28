import logging
import os

import tomli

LOGGER = logging.getLogger(__name__)


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.ERROR
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
    )
    LOGGER.setLevel(level)
    if verbose:
        LOGGER.debug("Verbose mode ON.")


def get_version() -> str:
    pyproject_path = os.path.join(os.path.dirname(__file__), "../../../pyproject.toml")
    with open(pyproject_path, "rb") as f:
        data = tomli.load(f)
    return data["project"]["version"]
