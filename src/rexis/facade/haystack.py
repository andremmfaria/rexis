import json
from typing import Any, Dict, List

import numpy as np
from haystack.components.embedders import OpenAIDocumentEmbedder
from haystack.components.preprocessors import DocumentSplitter
from haystack.components.writers import DocumentWriter
from haystack.dataclasses import Document
from haystack.document_stores.types import DuplicatePolicy
from haystack.utils import Secret
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.utils.config import config
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING
from rexis.utils.utils import LOGGER


def index_documents(documents: List[Document], refresh: bool = True) -> None:
    if not documents:
        LOGGER.warning("No documents provided for indexing.")
        return

    LOGGER.info("Starting indexing for %d documents...", len(documents))

    prepped_docs: List[Document] = _prepare_documents_for_indexing(documents)
    chunked_docs: List[Document] = _split_documents(prepped_docs)
    embedded_chunks: List[Document] = _embed_chunks(chunked_docs)
    rejoined_documents: List[Document] = _rejoin_embedded_chunks(embedded_chunks)
    _write_documents_to_db(rejoined_documents, refresh=refresh)
    LOGGER.info("Indexing complete.")
    
    
def _prepare_documents_for_indexing(documents: List[Document]) -> List[Document]:
    prepped_docs: List[Document] = []
    for doc in documents:
        if not isinstance(doc.content, str):
            try:
                doc.content = json.dumps(doc.content)
            except Exception:
                doc.content = str(doc.content)
        meta = dict(doc.meta or {})
        meta.setdefault("parent_id", doc.id)
        prepped_docs.append(Document(id=doc.id, content=doc.content, meta=meta))
    return prepped_docs


def _split_documents(documents: List[Document]) -> List[Document]:
    # Create a DocumentSplitter instance to split documents by words,
    # with each chunk containing up to 400 words and 50 words overlap between chunks.
    splitter: DocumentSplitter = DocumentSplitter(
        split_by="word",
        split_length=400,
        split_overlap=50,
        respect_sentence_boundary=False,
    )

    LOGGER.info("Splitting documents into chunks (word-based, length=400, overlap=50)...")

    # Run the splitter on the input documents. This returns a dict with a "documents" key.
    split_result = splitter.run(documents=documents)

    # Extract the list of split (chunked) documents from the result.
    chunked_docs: List[Document] = split_result.get("documents", [])

    LOGGER.info(
        "Chunking complete. %d chunks produced from %d input documents.",
        len(chunked_docs),
        len(documents),
    )

    # Group the chunked documents by their parent document ID.
    by_parent: Dict[str, List[Document]] = {}
    for d in chunked_docs:
        parent_id = d.meta.get("parent_id") or d.id
        if parent_id not in by_parent:
            by_parent[parent_id] = []
        by_parent[parent_id].append(d)

    # For each group of chunks belonging to the same parent document:
    for parent_id, chunks in by_parent.items():
        total = len(chunks)
        # Assign chunk index and total chunk count metadata, and set a unique chunk ID.
        for idx, ch in enumerate(chunks):
            ch.meta["chunk_index"] = idx
            ch.meta["total_chunks"] = total
            ch.id = f"{parent_id}::chunk-{idx}"

    # Return the list of all chunked documents.
    return chunked_docs


def _embed_chunks(chunked_docs: List[Document]) -> List[Document]:
    embedder: OpenAIDocumentEmbedder = OpenAIDocumentEmbedder(
        api_key=Secret.from_token(config.models.openai.api_key),
        model=config.models.openai.embedding_model,
    )
    LOGGER.info("Embedding %d chunked documents...", len(chunked_docs))
    emb_result = embedder.run(documents=chunked_docs)
    embedded_chunks: List[Document] = emb_result["documents"]
    LOGGER.info("Embedding complete. %d chunks embedded.", len(embedded_chunks))
    return embedded_chunks


def _rejoin_embedded_chunks(embedded_chunks: List[Document]) -> List[Document]:
    # Group chunks by their parent_id (or their own id if parent_id is missing)
    grouped_chunks: Dict[str, List[Document]] = {}
    for ch in embedded_chunks:
        parent_id: str = ch.meta.get("parent_id", ch.id)
        # Initialize the list if this parent_id hasn't been seen yet
        if parent_id not in grouped_chunks:
            grouped_chunks[parent_id] = []
        grouped_chunks[parent_id].append(ch)

    LOGGER.info("Rejoining embedded chunks back to parent documents...")
    rejoined_documents: List[Document] = []
    for parent_id, chunks in grouped_chunks.items():
        # If there's only one chunk and it's not a split chunk, just keep it as is
        if len(chunks) == 1 and "::chunk-" not in chunks[0].id:
            rejoined_documents.extend(chunks)
            continue

        # Collect all available embeddings for the chunks
        vecs: List[np.ndarray] = [
            np.array(ch.embedding, dtype=np.float32) for ch in chunks if ch.embedding is not None
        ]
        if not vecs:
            # If no embeddings are found, skip this group
            LOGGER.warning("No embeddings found for parent_id=%s; skipping.", parent_id)
            continue
        # Average the embeddings to create a single embedding for the rejoined document
        avg_embedding: List[float] = np.mean(vecs, axis=0).tolist()
        # Combine the content of all chunks, sorted by their chunk_index
        combined_content: str = "\n\n".join(
            ch.content for ch in sorted(chunks, key=lambda x: x.meta.get("chunk_index", 0))
        )
        # Copy the metadata from the first chunk, removing chunk-specific keys
        base_meta: Dict[str, Any] = dict(chunks[0].meta or {})
        base_meta.pop("chunk_index", None)
        base_meta.pop("total_chunks", None)
        # Create a new Document representing the rejoined parent document
        rejoined_documents.append(
            Document(
                id=parent_id,
                content=combined_content,
                embedding=avg_embedding,
                meta=base_meta,
            )
        )
    LOGGER.info("Rejoin complete. %d parent documents ready to write.", len(rejoined_documents))
    return rejoined_documents


def _write_documents_to_db(documents: List[Document], refresh: bool = True) -> None:
    LOGGER.info("Connecting to PgvectorDocumentStore...")
    doc_store: PgvectorDocumentStore = PgvectorDocumentStore(
        connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
        embedding_dimension=1536,
        vector_function="cosine_similarity",
        recreate_table=False,
        search_strategy="hnsw",
        hnsw_recreate_index_if_exists=True,
    )
    writer: DocumentWriter = DocumentWriter(
        document_store=doc_store,
        policy=DuplicatePolicy.OVERWRITE if refresh else DuplicatePolicy.SKIP,
    )
    LOGGER.info("Writing %d documents to database (refresh=%s)...", len(documents), refresh)
    writer.run(documents=documents)
