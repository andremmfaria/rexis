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


def process_metadata_for_embedding(file_hash: str) -> Dict[str, Any]:
    """
    Processes the metadata retrieved from VirusTotal and formats it for embedding into Haystack AI.

    Args:
        file_hash (str): The hash of the file to retrieve and process metadata for.

    Returns:
        Dict[str, Any]: A dictionary containing the processed metadata ready for embedding.
    """
    LOGGER.info(f"Starting to process metadata for file hash: {file_hash}")
    try:
        metadata = get_malware_metadata(file_hash)
        LOGGER.info(f"Metadata retrieved successfully for file hash: {file_hash}")

        # Extract relevant fields for embedding
        processed_metadata = {
            "file_hash": file_hash,
            "scan_date": metadata.get("scan_date"),
            "positives": metadata.get("positives"),
            "total": metadata.get("total"),
            "permalink": metadata.get("permalink"),
            "file_type": metadata.get("type"),
            "file_size": metadata.get("size"),
            "additional_info": metadata.get("additional_info", {}),
        }

        LOGGER.info(f"Metadata processed successfully for file hash: {file_hash}")
        return processed_metadata
    except Exception as e:
        LOGGER.error(f"Error processing metadata for file hash {file_hash}: {e}")
        raise
