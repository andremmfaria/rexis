import json
from typing import Dict, List, Literal

import tiktoken
from haystack.components.embedders import OpenAIDocumentEmbedder
from haystack.components.preprocessors import DocumentSplitter
from haystack.components.writers import DocumentWriter
from haystack.dataclasses import Document
from haystack.document_stores.types import DuplicatePolicy
from haystack.utils import Secret
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.facade.tagger import tag_chunk
from rexis.utils.config import config
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING
from rexis.utils.utils import LOGGER


def index_documents(
    documents: List[Document], refresh: bool = True, doc_type: Literal["prose", "json"] = "prose"
) -> None:
    """
    Index documents with chunking strategy based on doc_type.
    doc_type: 'prose' for English/natural language, 'json' for JSON/technical files.
    """
    if not documents:
        LOGGER.warning("No documents provided for indexing.")
        return

    print(f"Starting indexing for {len(documents)} documents (type={doc_type})...")

    prepped_docs: List[Document] = _prepare_documents_for_indexing(documents)
    chunked_docs: List[Document] = _split_documents(prepped_docs, doc_type=doc_type)
    embedded_chunks: List[Document] = _embed_chunks(chunked_docs)
    _write_documents_to_db(embedded_chunks, refresh=refresh)
    print("Indexing complete.")


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


def _split_documents(documents: List[Document], doc_type: str = "prose") -> List[Document]:
    if doc_type == "prose":
        splitter = DocumentSplitter(
            split_by="word",
            split_length=500,
            split_overlap=50,
            respect_sentence_boundary=True,
        )
        LOGGER.info("Splitting documents into chunks (word-based, length=500, overlap=50)...")
    elif doc_type == "json":
        splitter = DocumentSplitter(
            split_by="character",
            split_length=4000,
            split_overlap=400,
        )
        LOGGER.info(
            "Splitting documents into chunks (character-based, length=4000, overlap=400)..."
        )
    else:
        raise ValueError(f"Unknown doc_type: {doc_type}")

    splitter.warm_up()
    split_result = splitter.run(documents=documents)
    chunked_docs: List[Document] = split_result.get("documents", [])

    # Get model and limit from config
    embedding_model = config.models.openai.embedding_model
    max_tokens = getattr(config.models.openai, "embedding_model_limit", 8192)
    enc = tiktoken.encoding_for_model(embedding_model)

    def split_by_tokens(text: str, max_tokens: int) -> list:
        tokens = enc.encode(text)
        if len(tokens) <= max_tokens:
            return [text]
        # Split tokens into even chunks
        chunks = []
        for i in range(0, len(tokens), max_tokens):
            chunk_tokens = tokens[i : i + max_tokens]
            chunk_text = enc.decode(chunk_tokens)
            chunks.append(chunk_text)
        return chunks

    safe_chunks: List[Document] = []
    for d in chunked_docs:
        tokens = enc.encode(d.content)
        if len(tokens) > max_tokens:
            subchunks = split_by_tokens(d.content, max_tokens)
            for i, sub in enumerate(subchunks):
                new_doc = Document(
                    id=f"{d.id}::subchunk-{i}",
                    content=sub,
                    meta=dict(d.meta),
                )
                safe_chunks.append(new_doc)
        else:
            safe_chunks.append(d)

    print(
        f"Chunking complete. {len(safe_chunks)} chunks produced from {len(documents)} input documents."
    )

    # Group the chunked documents by their parent document ID.
    by_parent: Dict[str, List[Document]] = {}
    for d in safe_chunks:
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
            print(f"Chunk created: {ch.id} (parent: {parent_id}, index: {idx}/{total})")

    # --- Tagging: Add LLM-generated tags to each chunk's metadata ---
    for chunk in safe_chunks:
        tags = tag_chunk(chunk.content)
        LOGGER.info(f"Generated tags for chunk {chunk.id}: {tags}")
        if tags:
            chunk.meta["tags"] = tags
        else:
            chunk.meta["tags"] = []

    return safe_chunks


def _embed_chunks(chunked_docs: List[Document]) -> List[Document]:
    embedder: OpenAIDocumentEmbedder = OpenAIDocumentEmbedder(
        api_key=Secret.from_token(config.models.openai.api_key),
        model=config.models.openai.embedding_model,
    )
    print(f"Embedding {len(chunked_docs)} chunked documents...")
    emb_result = embedder.run(documents=chunked_docs)
    embedded_chunks: List[Document] = emb_result["documents"]
    print(f"Embedding complete. {len(embedded_chunks)} chunks embedded.")
    return embedded_chunks


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
