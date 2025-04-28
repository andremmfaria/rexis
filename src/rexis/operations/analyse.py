from haystack import Pipeline
from haystack.components.builders import PromptBuilder
from haystack.components.generators import OpenAIGenerator
from haystack.utils import Secret
from haystack_integrations.components.retrievers.pgvector import PgvectorKeywordRetriever
from haystack_integrations.document_stores.pgvector import PgvectorDocumentStore
from rexis.utils.config import settings
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING
from rexis.utils.utils import LOGGER


def build_query_pipeline() -> Pipeline:
    LOGGER.info("Building query pipeline...")

    # Document Store (same as before)
    LOGGER.info("Initializing PgvectorDocumentStore...")
    doc_store = PgvectorDocumentStore(
        connection_string=Secret.from_token(DATABASE_CONNECTION_CONNSTRING),
        embedding_dimension=1536,
        vector_function="cosine_similarity",
        recreate_table=False,
        search_strategy="hnsw",
        hnsw_recreate_index_if_exists=False,
    )

    # Retriever using document store
    LOGGER.info("Initializing PgvectorKeywordRetriever...")
    retriever = PgvectorKeywordRetriever(document_store=doc_store)

    LOGGER.info("Initializing PromptBuilder...")
    prompt_builder = PromptBuilder(
        template=settings.pipeline_params.prompt_template, required_variables=["query", "documents"]
    )

    # Generator (GPT-4o)
    LOGGER.info("Initializing OpenAIGenerator...")
    generator = OpenAIGenerator(
        api_key=Secret.from_token(settings.models.openai.api_key),
        model=settings.models.openai.query_model,
    )

    # Build pipeline
    LOGGER.info("Adding components to the pipeline...")
    pipe = Pipeline()
    pipe.add_component("retriever", retriever)
    pipe.add_component("prompt_builder", prompt_builder)
    pipe.add_component("llm", generator)

    # Correct connections:
    LOGGER.info("Connecting pipeline components...")
    pipe.connect("retriever.documents", "prompt_builder.documents")
    pipe.connect("prompt_builder.prompt", "llm.prompt")

    LOGGER.info("Pipeline built successfully.")
    return pipe


def analyse(query: str) -> str:
    LOGGER.info("Starting analysis for query: %s", query)
    pipeline = build_query_pipeline()

    LOGGER.info("Running pipeline...")
    result = pipeline.run(
        data={
            "retriever": {"query": query, "top_k": settings.pipeline_params.retriever_top_k},
            "prompt_builder": {"query": query},
        }
    )

    LOGGER.info("Pipeline execution completed.")
    LOGGER.info("GPT-4o Answer:\n%s", result["llm"]["replies"][0])

    return result["llm"]["replies"][0]
