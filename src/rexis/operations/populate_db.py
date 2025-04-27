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
from rexis.utils.utils import chunked
from tqdm import tqdm


def fetch_malware_documents(query_type: str, query_value: str, amount=500) -> List[Document]:
    """
    Fetches malware documents from the Malware Bazaar API based on the specified query type and value.

    Args:
        query_type (str): The type of query to perform (e.g., "tag", "hash").
        query_value (str): The value associated with the query type (e.g., a specific tag or hash value).
        amount (int, optional): The maximum number of results to fetch. Defaults to 500.

    Returns:
        List[Document]: A list of `Document` objects containing the fetched malware data. Each document includes:
            - `id`: The SHA256 hash of the malware sample.
            - `content`: A JSON string representation of the sample data.
            - `meta`: A dictionary containing metadata such as:
                - `sha256`: The SHA256 hash of the sample.
                - `tags`: A list of tags associated with the sample.
                - `file_type`: The file type of the sample.
                - `file_type_mime`: The MIME type of the sample.

    Notes:
        - If no results are found or the API response does not contain data, an empty list is returned.
        - The function queries the Malware Bazaar API and processes the response to extract relevant information.
    """
    print(f"Querying Malware Bazaar for {query_type}: {query_value}...")
    result = query_malware_bazaar(query_type=query_type, query_value=query_value, amount=amount)

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


def index_documents(documents: List[Document], batch_size: int = 50) -> None:
    """
    Indexes a list of documents into a pgvector-backed document store using an embedding and writing pipeline.

    Args:
        documents (List[Document]): A list of documents to be indexed. Each document should conform to the expected
            structure required by the embedding and document store components.
        batch_size (int, optional): The number of documents to process in each batch. Defaults to 50.

    Raises:
        Exception: If there are issues with connecting to the document store, generating embeddings, or writing
            documents to the store.

    Workflow:
        1. Connects to a pgvector-backed document store using the provided connection string and configuration.
        2. Initializes an embedding component using OpenAI's embedding model and API key.
        3. Sets up a document writing component with a policy to handle duplicate documents.
        4. Constructs a pipeline that connects the embedding and writing components.
        5. Processes the documents in batches, generating embeddings and writing them to the document store.
        6. Logs the progress and the total number of documents indexed.

    Note:
        - Ensure that the `DATABASE_CONNECTION_CONNSTRING` and OpenAI API key are correctly configured in the
          environment or settings.
        - The embedding model and other configurations should match the requirements of the document store.

    Example:
        >>> documents = [Document(content="Example 1"), Document(content="Example 2")]
        >>> index_documents(documents, batch_size=10)
    """
    # Step 1: Connect to your pgvector-backed document store
    doc_store: PgvectorDocumentStore = PgvectorDocumentStore(
        connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
        embedding_dimension=1536,
        vector_function="cosine_similarity",
        recreate_table=False,
        search_strategy="hnsw",
        hnsw_recreate_index_if_exists=True,
    )

    # Step 2: Create embedding + write pipeline
    embedder: OpenAIDocumentEmbedder = OpenAIDocumentEmbedder(
        api_key=Secret.from_token(settings.models.openai.api_key),
        model=settings.models.openai.embedding_model,
    )
    writer: DocumentWriter = DocumentWriter(
        document_store=doc_store, policy=DuplicatePolicy.OVERWRITE
    )

    pipeline: Pipeline = Pipeline()
    pipeline.add_component("embedder", embedder)
    pipeline.add_component("writer", writer)
    pipeline.connect("embedder.documents", "writer.documents")

    # Step 3: Run the pipeline
    for batch in tqdm(chunked(documents, batch_size), total=(len(documents) // batch_size) + 1):
        pipeline.run(data={"embedder": {"documents": batch}})
        print(f"Indexed {len(batch)} documents.\n")

    print(f"Indexed {len(documents)} documents.")
