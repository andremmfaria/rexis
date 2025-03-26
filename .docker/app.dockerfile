# Base image with Python 3.13
FROM python:3-slim

# Set environment variables
ENV PDM_HOME=/root/.local
ENV PATH="${PDM_HOME}/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /rexis

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install PDM
RUN curl -sSL https://pdm.fming.dev/install-pdm.py | python3

# Copy project metadata and config
COPY ./ ./

# Install dependencies
RUN pdm install

# Default command (adjust this to your actual entry point)
CMD ["pdm", "run", "rexis"]
