from typing import Any, Dict

import vt
from rexis.utils.config import settings
from rexis.utils.utils import LOGGER


def query_virustotal(hash: str) -> Dict[Any, Any]:
    """
    Retrieves metadata for a malware sample from the VirusTotal API using its hash.

    Args:
        file_hash (str): The hash of the file to retrieve metadata for.

    Returns:
        Dict[Any, Any]: A dictionary containing the metadata of the malware sample.

    Raises:
        ValueError: If the metadata retrieval fails or the sample is not found.
    """
    LOGGER.info(f"Retrieving metadata for file hash: {hash}")
    client = vt.Client(settings.virus_total_api_key)

    try:
        result: vt.Object = client.get_object(f"/files/{hash}")
        if not result:
            LOGGER.warning(f"No metadata found for hash: {hash}")
            raise ValueError(f"No metadata found for hash: {hash}")
        LOGGER.info(f"Metadata successfully retrieved for hash: {hash}")
        return result.to_dict()
    except Exception as e:
        LOGGER.error(f"Error retrieving metadata for hash {hash}: {e}")
        raise ValueError(f"Error retrieving metadata: {e}")
    finally:
        client.close()
        LOGGER.info(f"VirusTotal client closed for hash: {hash}")
