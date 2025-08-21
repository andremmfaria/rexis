from typing import Any, Dict, List, Optional

from haystack import Document
from haystack.components.embedders import OpenAITextEmbedder
from haystack.utils import Secret
from haystack_integrations.components.retrievers.pgvector import (
    PgvectorEmbeddingRetriever,
    PgvectorKeywordRetriever,
)
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.utils.config import config


def dense_search(
    store: PgvectorDocumentStore,
    queries: List[str],
    top_k_dense: int,
    metadata_filters: Optional[Dict[str, Any]],
) -> List[Document]:
    text_embedder: OpenAITextEmbedder = OpenAITextEmbedder(
        model=config.models.openai.embedding_model,
        api_key=Secret.from_token(config.models.openai.api_key),
    )

    retriever: PgvectorEmbeddingRetriever = PgvectorEmbeddingRetriever(
        document_store=store,
        filters=metadata_filters,
        top_k=top_k_dense,
        vector_function="cosine_similarity",
    )

    best_by_id: Dict[str, Document] = {}
    for q in queries:
        emb: List[float] = text_embedder.run(q)["embedding"]  # returns a single vector for the query
        out: Dict[str, List[Document]] = retriever.run(query_embedding=emb, top_k=top_k_dense)
        for d in out["documents"]:
            prev: Optional[Document] = best_by_id.get(d.id)
            if prev is None or (d.score or 0) > (prev.score or 0):
                best_by_id[d.id] = d
    return list(best_by_id.values())


def keyword_search(
    store: PgvectorDocumentStore,
    queries: List[str],
    top_k_keyword: int,
    metadata_filters: Optional[Dict[str, Any]],
) -> List[Document]:
    """
    Run keyword retrieval across all queries, merging and keeping the best score per doc id.
    """
    retriever: PgvectorKeywordRetriever = PgvectorKeywordRetriever(
        document_store=store, filters=metadata_filters, top_k=top_k_keyword
    )
    best_by_id: Dict[str, Document] = {}
    for q in queries:
        out: Dict[str, List[Document]] = retriever.run(query=q, top_k=top_k_keyword)
        for d in out["documents"]:
            prev: Optional[Document] = best_by_id.get(d.id)
            if prev is None or (d.score or 0) > (prev.score or 0):
                best_by_id[d.id] = d
    return list(best_by_id.values())
