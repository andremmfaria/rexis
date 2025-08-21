from haystack.utils import Secret
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING


def init_store() -> PgvectorDocumentStore:
    """
    Match ingestion settings:
            - connection_string from env/config
            - 1536 dims (text-embedding-3-small)
            - cosine similarity
            - HNSW search
    """
    return PgvectorDocumentStore(
        connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
        embedding_dimension=1536,
        vector_function="cosine_similarity",
        recreate_table=False,
        search_strategy="hnsw",
        hnsw_recreate_index_if_exists=False,
    )
