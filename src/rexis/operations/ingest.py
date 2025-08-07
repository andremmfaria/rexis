import json
import uuid
from collections import defaultdict
from typing import Dict, Generator, List, Optional

import numpy as np
import tiktoken
from haystack.components.embedders import OpenAIDocumentEmbedder
from haystack.components.writers import DocumentWriter
from haystack.dataclasses import Document
from haystack.document_stores.types import DuplicatePolicy
from haystack.utils import Secret
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.facade.malware_bazaar import query_malware_bazaar
from rexis.facade.virus_total import query_virustotal
from rexis.utils.config import settings
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING
from rexis.utils.utils import LOGGER


def ingest_exec(
    hash: Optional[str],
    tags: Optional[List[str]],
    file_path: Optional[str],
    source: str,
    refresh: bool,
    limit: int = 100,
) -> None:
    """
    Dispatches ingestion tasks based on provided input parameters and sources, fetching documents from
    MalwareBazaar and/or VirusTotal, and indexes the retrieved documents.

    Parameters:
        hash (Optional[str]): A single hash hash to fetch documents for.
        tags (Optional[List[str]]): A list of tags to fetch documents by.
        limit (int): Maximum number of documents to fetch per tag.
        file_path (Optional[str]): Path to a file containing hash hashes (one per line).
        source (str): Comma-separated list of sources ("malwarebazaar", "virustotal", or "all").
        refresh (bool): Whether to refresh the data (overwrite existing entries).

    Behavior:
        - Normalizes the source input and determines which sources to query.
        - Determines the ingestion mode based on which input parameter is provided (hash, tags, file, since).
        - Fetches documents from the specified sources using the appropriate mode.
        - Handles file not found errors and invalid input gracefully.
        - Indexes all fetched documents if any are retrieved.

    Returns:
        None
    """

    def normalize_source(source_name: str) -> List[str]:
        src = source_name.lower()
        if src == "all":
            return ["malwarebazaar", "virustotal"]
        return [
            s.strip().lower()
            for s in src.split(",")
            if s.strip() in {"malwarebazaar", "virustotal"}
        ]

    sources = normalize_source(source)
    tasks = []
    if refresh:
        LOGGER.info("Refresh mode enabled: existing entries will be overwritten.")

    if hash:
        LOGGER.info(f"Ingesting by hash: {hash}")
        tasks.append(("hash", [hash]))
    elif file_path:
        try:
            with open(file_path, "r") as f:
                hashes = [line.strip() for line in f if line.strip()]
                LOGGER.info(f"Ingesting hashes from file: {file_path} ({len(hashes)} hashes)")
                tasks.append(("hash", hashes))
        except FileNotFoundError:
            LOGGER.info(f"File not found: {file_path}")
            return
    elif tags:
        LOGGER.info(f"Ingesting by tags: {', '.join(tags)}")
        tasks.append(("tags", tags))
    else:
        LOGGER.info("No valid input provided. Use --hash, --tags, or --file.")
        return

    all_documents = []

    for src in sources:
        for mode, values in tasks:
            if src == "malwarebazaar":
                if mode == "hash":
                    for hash in values:
                        LOGGER.info(f"Fetching from MalwareBazaar by hash-256: {hash}")
                        result = query_malware_bazaar(query_type="hash", query_value=hash, amount=1)
                        docs = _wrap_malwarebazaar_documents(result["data"])
                        all_documents.extend(docs)
                elif mode == "tags":
                    for tag in values:
                        LOGGER.info(f"Fetching from MalwareBazaar by tag: {tag} (limit={limit})")
                        result = query_malware_bazaar(
                            query_type="tag", query_value=tag, amount=limit
                        )
                        docs = _wrap_malwarebazaar_documents(result["data"])
                        all_documents.extend(docs)
                elif mode == "filetype":
                    for filetype in values:
                        LOGGER.info(
                            f"Fetching from MalwareBazaar by filetype: {filetype} (limit={limit})"
                        )
                        result = query_malware_bazaar(
                            query_type="filetype", query_value=filetype, amount=limit
                        )
                        docs = _wrap_malwarebazaar_documents(result["data"])
                        all_documents.extend(docs)
            elif src == "virustotal":
                if mode != "hash":
                    LOGGER.info(
                        "⚠️ VirusTotal public API only supports sample-by-hash queries. Skipping non-hash inputs."
                    )
                    continue
                for hash in values:
                    LOGGER.info(f"Fetching from VirusTotal by hash-256: {hash}")
                    vt_data = query_virustotal(hash=hash)
                    if not vt_data:
                        LOGGER.info(f"No data found in VirusTotal for hash: {hash}")
                        continue
                    docs = [
                        Document(
                            id=f"{hash}_vt",
                            content=json.dumps(vt_data),
                            meta={"source": "virustotal", "sha256": hash},
                        )
                    ]
                    all_documents.extend(docs)
    if all_documents:
        LOGGER.info(f"Indexing {len(all_documents)} documents...")
        index_documents(documents=all_documents, refresh=refresh)
        LOGGER.info("Indexing completed.")
    else:
        LOGGER.info("No documents fetched for indexing.")


def index_documents(documents: List[Document], refresh: bool) -> None:
    """
    Indexes a list of documents into a PostgreSQL vector database with chunking and embedding.

    Workflow:
        1. Splits documents into smaller chunks if they exceed the token limit for the embedding model.
        2. Embeds all (possibly chunked) documents using the specified OpenAI embedding model.
        3. Reassembles embedded chunks back into full documents by averaging their embeddings and concatenating their content.
        4. Writes the processed documents to a PgvectorDocumentStore, with optional overwrite behavior.

    Args:
        documents (List[Document]): List of Haystack Document objects to be indexed.
        refresh (bool): If True, existing documents with the same ID are overwritten; if False, duplicates are skipped.

    Raises:
        Exception: Any error during the indexing process is logged and re-raised.

    Notes:
        - Documents are split using tiktoken if they exceed the model's token limit.
        - Embedding is performed using OpenAIDocumentEmbedder.
        - Documents are written to a PostgreSQL vector store using Haystack's DocumentWriter.
        - Duplicate handling is controlled by the 'refresh' parameter.
    """
    if not documents:
        LOGGER.warning("No documents provided for indexing.")
        return

    LOGGER.info(f"Starting indexing for {len(documents)} documents...")

    encoding = tiktoken.encoding_for_model(settings.models.openai.embedding_model)
    max_tokens = settings.models.openai.embedding_model_limit
    chunked_documents = []
    split_parent_ids = set()

    for doc in documents:
        token_count = len(encoding.encode(doc.content))
        LOGGER.debug(f"Document ID: {doc.id} has {token_count} tokens.")
        if token_count > max_tokens:
            LOGGER.info(
                f"Splitting document ID: {doc.id} from {doc.meta.get('source', 'unknown')} into chunks (token count: {token_count}, max: {max_tokens})"
            )
            chunked = list(_split_document_into_chunks(doc, max_tokens, encoding))
            LOGGER.debug(f"Document ID: {doc.id} split into {len(chunked)} chunks.")
            chunked_documents.extend(chunked)
            split_parent_ids.add(doc.id)
        else:
            chunked_documents.append(doc)

    LOGGER.info(f"Total chunked documents to embed: {len(chunked_documents)}")

    if not chunked_documents:
        LOGGER.warning("No documents within token limit to index.")
        return

    try:
        # 1. Connect to vector store
        LOGGER.info("Connecting to PgvectorDocumentStore...")
        doc_store = PgvectorDocumentStore(
            connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
            embedding_dimension=1536,
            vector_function="cosine_similarity",
            recreate_table=False,
            search_strategy="hnsw",
            hnsw_recreate_index_if_exists=True,
        )

        # 2. Embed chunks
        embedder = OpenAIDocumentEmbedder(
            api_key=Secret.from_token(settings.models.openai.api_key),
            model=settings.models.openai.embedding_model,
        )
        LOGGER.info("Embedding chunked documents...")
        result = embedder.run(documents=chunked_documents)
        embedded_chunks: List[Document] = result["documents"]
        LOGGER.info(f"Embedding complete. {len(embedded_chunks)} chunks embedded.")

        # 3. Reassemble only those chunks that were actually split
        grouped_chunks: Dict[str, List[Document]] = defaultdict(list)
        for chunk in embedded_chunks:
            parent_id = chunk.meta.get("parent_id", chunk.id)
            grouped_chunks[parent_id].append(chunk)

        rejoined_documents: List[Document] = []
        for parent_id, chunks in grouped_chunks.items():
            if parent_id in split_parent_ids:
                LOGGER.debug(f"Rejoining {len(chunks)} chunks for parent_id: {parent_id}")
                rejoined_documents.append(_rejoin_chunks_into_document(chunks))
            else:
                # Not split, just take the single chunk (original doc)
                rejoined_documents.extend(chunks)

        LOGGER.info(f"Total documents to write: {len(rejoined_documents)}")

        # 4. Write to database
        writer = DocumentWriter(
            document_store=doc_store,
            policy=DuplicatePolicy.OVERWRITE if refresh else DuplicatePolicy.SKIP,
        )

        LOGGER.info(
            f"Writing {len(rejoined_documents)} documents to database (refresh={refresh})..."
        )
        writer.run(documents=rejoined_documents)
        LOGGER.info("Indexing complete.")

    except Exception as e:
        LOGGER.error(f"Failed to index documents: {e}", exc_info=True)
        raise


def _wrap_malwarebazaar_documents(api_data: List[dict]) -> List[Document]:
    """
    Converts MalwareBazaar API results into Haystack Document objects.

    For each sample in the input list:
        - Uses the 'sha256_hash' as the document ID.
        - Serializes the entire sample dictionary as the document content (JSON).
        - Sets the document metadata to include the source as 'malwarebazaar'.

    Args:
        api_data (List[dict]): List of dictionaries from MalwareBazaar API.

    Returns:
        List[Document]: List of Haystack Document objects representing the samples.
    """
    LOGGER.debug(f"Wrapping {len(api_data)} MalwareBazaar API results into Document objects.")
    documents = []
    for sample in api_data:
        hash: str = sample.get("sha256_hash", "")
        content: str = json.dumps(sample)
        LOGGER.debug(f"Creating Document for sha256: {hash} with content: {content}")
        documents.append(
            Document(
                id=f"{hash}_bz", content=content, meta={"source": "malwarebazaar", "sha256": hash}
            )
        )
    LOGGER.info(f"Wrapped {len(documents)} documents from MalwareBazaar API data.")
    return documents


def _split_document_into_chunks(
    document: Document, max_tokens: int, encoding
) -> Generator[Document, None, None]:
    """
    Splits a Document into smaller chunks based on token limits.

    Args:
        document (Document): Original document to split.
        max_tokens (int): Max tokens per chunk.
        encoding: tiktoken encoding instance.

    Yields:
        Document: Smaller document chunks with metadata.
    """
    tokens = encoding.encode(document.content)
    parent_id = document.id or str(uuid.uuid4())

    for i in range(0, len(tokens), max_tokens):
        chunk_tokens = tokens[i : i + max_tokens]
        chunk_text = encoding.decode(chunk_tokens)
        yield Document(
            id=f"{parent_id}-chunk-{i // max_tokens}",
            content=chunk_text,
            meta={
                **document.meta,
                "parent_id": parent_id,
                "chunk_index": i // max_tokens,
                "total_chunks": (len(tokens) + max_tokens - 1) // max_tokens,
            },
        )


def _rejoin_chunks_into_document(chunks: List[Document]) -> Document:
    """
    Reconstructs a full document from a list of chunked Document objects, aggregating their content and averaging their embeddings.

        chunks (List[Document]):
            A list of Document instances representing sequential chunks of the original document.
            All chunks must share the same parent_id and contain 'chunk_index' in their metadata.

        Document:
            A new Document instance representing the reassembled original document.
            The content is concatenated in the order of 'chunk_index', and the embedding is the mean of all chunk embeddings.
            Metadata is inherited from the first chunk, excluding chunk-specific keys.

    Raises:
        ValueError:
            If the input list is empty or if none of the chunks contain a valid embedding.

    Notes:
        - The function assumes that each chunk's metadata contains a 'chunk_index' key for correct ordering.
        - Chunk-specific metadata keys ('chunk_index', 'total_chunks') are removed from the resulting document's metadata.
    """
    if not chunks:
        raise ValueError("No chunks provided for rejoining.")

    sorted_chunks = sorted(chunks, key=lambda d: d.meta.get("chunk_index", 0))
    content = "\n".join(chunk.content for chunk in sorted_chunks)

    # Aggregate embeddings: average across all chunk vectors
    embeddings = [chunk.embedding for chunk in sorted_chunks if chunk.embedding is not None]
    if not embeddings:
        raise ValueError("No valid embeddings found in chunks.")

    embedding_array = np.array(embeddings, dtype=np.float32)
    averaged_embedding = embedding_array.mean(axis=0).tolist()

    # Use metadata from the first chunk, excluding chunk-specific keys
    base_meta = {
        k: v for k, v in sorted_chunks[0].meta.items() if k not in {"chunk_index", "total_chunks"}
    }

    return Document(
        id=base_meta.get("parent_id", str(uuid.uuid4())),
        content=content,
        embedding=averaged_embedding,
        meta=base_meta,
    )
