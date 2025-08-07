# Use a Java base image compatible with Ghidra 11.3.2 (requires JDK ≥21)
FROM eclipse-temurin:21-jdk-jammy

# Set environment variables
ENV GHIDRA_VERSION=11.3.2 \
    GHIDRA_HOME=/opt/ghidra \
    SCRIPT_DIR=/scripts \
    PROJECT_DIR=/ghidra_projects

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget unzip python3 python3-pip libxrender1 libxtst6 libxi6 \
    && rm -rf /var/lib/apt/lists/*

# Download and extract Ghidra 11.3.2
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250415.zip -O /tmp/ghidra.zip \
    && unzip /tmp/ghidra.zip -d /opt/ \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} \
    && rm -rf /tmp/ghidra.zip

# Copy static analysis script into the container
COPY ghidra_scripts/extract_pe_features.py ${SCRIPT_DIR}/

# Create required directories
RUN mkdir -p ${PROJECT_DIR} /samples /output

# Set working directory
WORKDIR ${GHIDRA_HOME}

# Set the default entrypoint to Ghidra headless analyzer
ENTRYPOINT ["./support/analyzeHeadless", "/ghidra_projects", "malware_analysis"]
