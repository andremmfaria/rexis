FROM postgres:15

# Install pgvector and any other required extensions
RUN apt-get update && \
    apt-get install -y postgresql-server-dev-15 build-essential git

RUN git clone --branch v0.5.1 https://github.com/pgvector/pgvector.git && \
    cd pgvector && \
    make && \
    make install && \
    cd .. && \
    rm -rf pgvector

RUN apt-get remove -y build-essential git && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Set default environment variables (can be overridden by Docker Compose or CLI)
# ENV POSTGRES_USER=postgres
# ENV POSTGRES_PASSWORD=super_secret_password
# ENV POSTGRES_DB=rexis

# Optional: Create the vector extension on init
COPY .docker/database/init.sql /docker-entrypoint-initdb.d/init.sql
