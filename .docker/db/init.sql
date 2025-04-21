-- Enable the pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create the documents table with a vector column
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    embedding VECTOR(1536) -- 1536-dimensional vector
);

-- (Optional) Create an index for faster similarity search
-- Choose the similarity metric you plan to use: cosine, euclidean, or inner product
-- Here we use cosine similarity as an example
CREATE INDEX documents_embedding_idx
ON documents USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);
