import json
from typing import List

from haystack import Pipeline
from haystack.components.embedders import OpenAIDocumentEmbedder
from haystack.components.writers import DocumentWriter
from haystack.dataclasses import Document
from haystack.document_stores.types import DuplicatePolicy
from haystack.utils import Secret
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.facade.malware_bazaar import Sample, query_malware_bazaar
from rexis.utils.config import settings
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING


def fetch_malware_documents(query_type: str, query_value: str) -> List[Document]:
    """
    Fetch malware documents from Malware Bazaar based on the given query type and value.

    Args:
        query_type (str): The type of query to perform (e.g., "tag", "hash").
        query_value (str): The value to query for (e.g., specific tag or hash).

    Returns:
        List[Document]: A list of Document objects containing the fetched malware data.
    """
    print(f"Querying Malware Bazaar for {query_type}: {query_value}...")
    result = query_malware_bazaar(query_type=query_type, query_value=query_value)

    if not result or "data" not in result:
        print("No results.")
        return []

    documents: List[Document] = []

    sample: Sample
    for sample in result["data"]:
        sha256: str = sample.get("sha256_hash", "")
        content: str = json.dumps(sample, indent=2)
        tags: List[str] = list(
            set(
                sample.get("tags", [])
                + [sample.get("signature")]
                + (sample.get("intelligence", {}).get("clamav") or [])
            )
        )
        tags = [tag for tag in tags if tag and isinstance(tag, str)]
        file_type: str = sample.get("file_type", "")
        file_type_mime: str = sample.get("file_type_mime", "")

        documents.append(
            Document(
                id=sha256,
                content=content,
                meta={
                    "sha256": sha256,
                    "tags": tags,
                    "file_type": file_type,
                    "file_type_mime": file_type_mime,
                },
            )
        )

    return documents


def index_documents(documents: List[Document]) -> None:
    """
    Index the given documents into a pgvector-backed document store.

    Args:
        documents (List[Document]): A list of Document objects to be indexed.

    Returns:
        None
    """
    # Step 1: Connect to your pgvector-backed document store
    doc_store: PgvectorDocumentStore = PgvectorDocumentStore(
        connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
        embedding_dimension=1536,
        vector_function="cosine_similarity",
        recreate_table=False,
        search_strategy="hnsw",
        hnsw_recreate_index_if_exists=True
    )

    # Step 2: Create embedding + write pipeline
    embedder: OpenAIDocumentEmbedder = OpenAIDocumentEmbedder(
        api_key=Secret.from_token(settings.models.openai.api_key),
        model=settings.models.openai.embedding_model,
    )
    writer: DocumentWriter = DocumentWriter(document_store=doc_store, policy=DuplicatePolicy.OVERWRITE)

    pipeline: Pipeline = Pipeline()
    pipeline.add_component("embedder", embedder)
    pipeline.add_component("writer", writer)
    pipeline.connect("embedder.documents", "writer.documents")

    # Step 3: Run the pipeline
    pipeline.run(data={"embedder": {"documents": documents}})

    print(f"Indexed {len(documents)} documents.")
