import json
import time
from pathlib import Path
from typing import List, Optional, Tuple

from haystack import Document
from rexis.facade.haystack import index_documents
from rexis.facade.malware_bazaar import query_malware_bazaar
from rexis.utils.utils import LOGGER


def ingest_api_exec(
    tags: Optional[str] = None,
    fetch_limit: Optional[int] = None,
    batch: Optional[int] = None,
    hash: Optional[str] = None,
    hash_file: Optional[Path] = None,
) -> None:
    tasks = _build_ingest_tasks(tags, fetch_limit, batch, hash, hash_file)
    if not tasks:
        return

    for mode, values in tasks:
        if mode == "hash":
            _ingest_by_hash(values, batch)
        elif mode == "tags":
            _ingest_by_tags(values, fetch_limit, batch)


def _build_ingest_tasks(
    tags: Optional[str],
    fetch_limit: Optional[int],
    batch: Optional[int],
    hash: Optional[str],
    hash_file: Optional[Path],
) -> List[Tuple[str, List[str]]]:
    tasks: List[Tuple[str, List[str]]] = []

    if hash:
        LOGGER.info(f"Ingesting by hash: {hash}")
        tasks.append(("hash", [hash]))

    elif hash_file:
        try:
            with open(hash_file, "r", encoding="utf-8") as f:
                hashes = [line.strip() for line in f if line.strip()]
            LOGGER.info(f"Ingesting hashes from file: {hash_file} ({len(hashes)} hashes)")
            tasks.append(("hash", hashes))
        except FileNotFoundError:
            LOGGER.error(f"File not found: {hash_file}")
            return []

    elif tags:
        tag_list: List[str] = [t.strip() for t in tags.split(",") if t.strip()]
        if fetch_limit is None or fetch_limit <= 0:
            LOGGER.error("--fetch_limit must be provided and > 0 when using --tags.")
            return []
        if batch is None or batch <= 0:
            LOGGER.error("--batch must be provided and > 0 when using --tags.")
            return []
        LOGGER.info(
            f"Ingesting by tags: {', '.join(tag_list)} (fetch_limit={fetch_limit}, batch={batch})"
        )
        tasks.append(("tags", tag_list))

    else:
        LOGGER.error("No valid input provided. Use --hash, --tags, or --hash_file.")
        return []

    return tasks


def _process_and_index(documents_batch):
    documents_batch: List[Document]
    if documents_batch:
        LOGGER.info(f"Indexing {len(documents_batch)} documents...")
        index_documents(documents=documents_batch, refresh=True, doc_type="json")
        LOGGER.info("Batch indexing completed.")


def _ingest_by_hash(hashes: List[str], batch: Optional[int]):
    # Log the start of the ingestion process, including the number of hashes and batch size
    LOGGER.info(
        f"Starting ingestion by hash for {len(hashes)} hashes. Batch size: {batch if batch else 'all'}."
    )
    all_documents: List[Document] = []
    total_hashes = len(hashes)
    batch_size = batch if batch else total_hashes
    num_batches = (total_hashes + batch_size - 1) // batch_size
    current_batch = 1

    # Iterate over each hash, fetching and processing documents
    for idx, h in enumerate(hashes, 1):
        LOGGER.info(f"[Hash] Fetching from MalwareBazaar by hash-256: {h} ({idx}/{total_hashes})")
        try:
            # Query MalwareBazaar for the current hash
            result = query_malware_bazaar(query_type="hash", query_value=h, amount=1)
        except Exception as e:
            LOGGER.error(f"Exception querying MalwareBazaar for hash {h}: {e}")
            continue
        if not result or "data" not in result:
            LOGGER.warning(f"No data returned for hash {h}")
            continue
        # Wrap the API result into Document objects
        docs = _wrap_malwarebazaar_documents(result["data"])
        all_documents.extend(docs)

        # If the batch size is reached, process and index the batch
        if batch and len(all_documents) >= batch:
            LOGGER.info(
                f"[Hash] Processing batch {current_batch} of {num_batches} (batch size: {batch})"
            )
            _process_and_index(all_documents)
            all_documents = []
            current_batch += 1

    # Process any remaining documents that didn't fill a complete batch
    if all_documents:
        LOGGER.info(
            f"[Hash] Processing batch {current_batch} of {num_batches} (batch size: {len(all_documents)})"
        )
        _process_and_index(all_documents)

    LOGGER.info(f"Completed ingestion by hash. Total hashes processed: {total_hashes}.")


def _ingest_by_tags(tags: List[str], fetch_limit: int, batch: int):
    # Log the start of the ingestion process with the provided tags, fetch limit, and batch size
    LOGGER.info(f"Starting ingestion by tags: {tags} | fetch_limit={fetch_limit} | batch={batch}")
    all_documents: List[Document] = []
    docs_per_tag: List[int] = []

    # First, query MalwareBazaar for each tag to count the number of documents per tag
    for tag in tags:
        try:
            result = query_malware_bazaar(query_type="tag", query_value=tag, amount=fetch_limit)
        except Exception as e:
            LOGGER.error(f"Exception querying MalwareBazaar for tag {tag}: {e}")
            continue
        if not result or "data" not in result:
            LOGGER.warning(f"No data returned for tag {tag}")
            continue
        docs_per_tag.append(len(result["data"]))

    # Calculate the total number of documents to be ingested across all tags
    grand_total_docs = sum(docs_per_tag)
    if grand_total_docs == 0:
        LOGGER.warning("No documents found for any tag.")
        return

    # Determine the number of batches needed
    num_batches = (grand_total_docs + batch - 1) // batch
    current_batch = 1
    doc_counter = 0

    # For each tag, fetch the documents and process them in batches
    for tag in tags:
        LOGGER.info(f"[Tags] Fetching from MalwareBazaar by tag: {tag} (limit={fetch_limit})")
        try:
            result = query_malware_bazaar(query_type="tag", query_value=tag, amount=fetch_limit)
        except Exception as e:
            LOGGER.error(f"Exception querying MalwareBazaar for tag {tag}: {e}")
            continue
        if not result or "data" not in result:
            LOGGER.warning(f"No data returned for tag {tag}")
            continue

        # Wrap the API results into Document objects
        docs = _wrap_malwarebazaar_documents(result["data"])
        for doc in docs:
            all_documents.append(doc)
            doc_counter += 1
            # If the batch size is reached, process and index the batch
            if len(all_documents) >= batch:
                LOGGER.info(
                    f"[Tags] Processing batch {current_batch} of {num_batches} (batch size: {batch}) [{doc_counter}/{grand_total_docs} docs]"
                )
                _process_and_index(all_documents)
                all_documents = []
                current_batch += 1

    # Process any remaining documents that didn't fill a complete batch
    if all_documents:
        LOGGER.info(
            f"[Tags] Processing batch {current_batch} of {num_batches} (batch size: {len(all_documents)}) [{doc_counter}/{grand_total_docs} docs]"
        )
        _process_and_index(all_documents)

    LOGGER.info(f"Completed ingestion by tags. Total docs processed: {grand_total_docs}.")


def _wrap_malwarebazaar_documents(api_data: List[dict]) -> List[Document]:
    """
    Transforms a List of MalwareBazaar API result dictionaries into a List of Haystack Document objects.

    Each API result is serialized to JSON and wrapped in a Document, with the SHA256 hash used as part of the document ID
    and included in the metadata. Also adds tags, timestamps, and imported time to the metadata.

    Args:
        api_data (List[dict]): A List of dictionaries, each representing a sample returned by the MalwareBazaar API.

    Returns:
        List[Document]: A List of Haystack Document objects, each containing the serialized sample data and metadata.

    Logs:
        - The number of API results being wrapped.
        - The SHA256 hash for each sample as it is processed.
        - The total number of documents created.
    """

    LOGGER.debug(f"Wrapping {len(api_data)} MalwareBazaar API results into Document objects.")
    documents: List[Document] = []
    imported_time: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sample: dict
    for sample in api_data:
        hash_val: str = sample.get("sha256_hash", "")
        content: str = json.dumps(sample)
        tags: List = sample.get("tags", [])
        # Try to get timestamp fields, fallback to None if not present
        first_seen = sample.get("first_seen", None)
        last_seen = sample.get("last_seen", None)
        LOGGER.debug(f"Creating Document for sha256: {hash_val}")
        documents.append(
            Document(
                id=f"api_mb::{hash_val}",
                content=content,
                meta={
                    "sha256": hash_val,
                    "tags": tags,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "imported_time": imported_time,
                },
            )
        )
    LOGGER.info(f"Wrapped {len(documents)} documents from MalwareBazaar API data.")
    return documents
