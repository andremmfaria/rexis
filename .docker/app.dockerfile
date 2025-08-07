# Base image with Python 3.13
FROM python:3-slim

# Set environment variables
ENV PDM_HOME=/root/.local
ENV PATH="${PDM_HOME}/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GHIDRA_HOME=/opt/ghidra

# Set working directory
WORKDIR /rexis

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        clang \
        curl \
        git \
        openjdk-11-jdk \
        unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install PDM
RUN curl -sSL https://pdm.fming.dev/install-pdm.py | python3

# Install Ghidra
RUN GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep "browser_download_url.*ghidra.*zip" | cut -d '"' -f 4) \
    && curl -L -o /tmp/ghidra.zip "$GHIDRA_URL" \
    && mkdir -p $GHIDRA_HOME \
    && unzip /tmp/ghidra.zip -d $GHIDRA_HOME \
    && rm /tmp/ghidra.zip

# Copy project metadata and config
COPY ./ ./

# Install dependencies
RUN pdm install

# Default command (adjust this to your actual entry point)
CMD ["pdm", "run", "rexis"]
