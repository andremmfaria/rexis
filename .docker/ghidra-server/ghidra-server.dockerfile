FROM blacktop/ghidra:11.4

ENV MCPO_PORT=8001 \
    MCPO_HOST=0.0.0.0 \
    MCPO_API_KEY=80cf012afad040e4bb7c940f44f8070c \
    FASTMCP_HOST=127.0.0.1 \
    FASTMCP_PORT=8000 \
    GHIDRA_INSTALL_DIR=/ghidra \
    GHIDRA_MAXMEM=4G \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

# ---- OS deps + Python venv ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates wget unzip \
  && rm -rf /var/lib/apt/lists/* \
  && python3 -m venv "$VIRTUAL_ENV" \
  && "$VIRTUAL_ENV/bin/pip" install --upgrade pip \
  && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir \
        pyghidra \
        pyghidra-mcp \
        mcpo

# Work dirs (mounted from host)
RUN mkdir -p /binaries /workspace
VOLUME ["/binaries", "/workspace"]

# Start script (unchanged)
COPY .docker/ghidra-server/start-ghidra-mcpo.sh /usr/local/bin/start-ghidra-mcpo.sh
RUN chmod +x /usr/local/bin/start-ghidra-mcpo.sh

EXPOSE 8000
CMD ["/usr/local/bin/start-ghidra-mcpo.sh"]
