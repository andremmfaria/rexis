import json

import psycopg2
from psycopg2.errors import UniqueViolation
from rexis.facade.ai_provider import OpenAIProvider
from rexis.facade.malware_bazaar import query_malware_bazaar
from rexis.utils.constants import DATABASE_CONNECTION_CONNSTRING


def populate_db(query_type: str, query_value: str) -> None:
    """
    Populate the database with malware samples and their embeddings.

    This function queries the Malware Bazaar API for malware samples based on the
    specified query type and value. It processes the samples, generates embeddings
    using the OpenAIProvider, and stores the data in a PostgreSQL database.

    Args:
        query_type (str): The type of query to perform (e.g., "hash", "tag").
        query_value (str): The value to query for (e.g., a specific hash or tag).

    Returns:
        None
    """
    print(f"Querying Malware Bazaar for {query_type}: {query_value}...")
    result = query_malware_bazaar(query_type=query_type, query_value=query_value)

    print(f"{len(result)} samples received. Preparing for storage...")

    conn = psycopg2.connect(DATABASE_CONNECTION_CONNSTRING)
    cur = conn.cursor()

    # Prepare inputs for embedding
    new_samples = []
    contents = []

    for sample in result:
        sha256 = sample.get("sha256_hash")
        if not sha256:
            continue
        content = json.dumps(sample, indent=2)
        contents.append(content)
        new_samples.append((sha256, content, sample))

    if not new_samples:
        print("No new samples to embed.")
        return

    print("Generating embeddings...")
    provider = OpenAIProvider()
    embeddings = provider.get_embeddings_batch(texts=[c for _, c, _ in new_samples])

    print("Inserting into database...")
    for (sha256, content, sample), embedding in zip(new_samples, embeddings):
        tags = list(
            set(
                sample.get("tags", [])
                + [sample.get("signature")]
                + [sample.get("vendor_intel", {}).get("clamav")]
            )
        )
        tags = [tag for tag in tags if tag and isinstance(tag, str)]

        try:
            cur.execute(
                """
                INSERT INTO documents (sha256, content, tags, embedding)
                VALUES (%s, %s, %s, %s)
            """,
                (sha256, content, tags, embedding),
            )
        except UniqueViolation:
            print(f"Duplicate sample: {sha256} — skipping.")
            conn.rollback()
        except Exception as err:
            print(f"Error inserting {sha256}: {err}")
            conn.rollback()

    conn.commit()
    cur.close()
    conn.close()
    print(f"Finished storing {len(new_samples)} samples.")
