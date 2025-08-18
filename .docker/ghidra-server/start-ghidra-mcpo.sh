#!/usr/bin/env bash
set -euo pipefail

# ── 0) Build the list of files to pre-import ────────────────────────────────
ROOTS="${MCP_INPUT_PATHS:-/binaries,/workspace}"
MAX="${MCP_PRELOAD_MAX:-1}"

mapfile -t PATHS < <(
  IFS=',' read -ra R <<< "$ROOTS"
  for r in "${R[@]}"; do
    if [ -f "$r" ]; then printf '%s\0' "$r"
    elif [ -d "$r" ] && [ "${MAX}" -gt 0 ]; then
      find "$r" -maxdepth 1 -type f -print0 | head -zn "$MAX"
    fi
  done | xargs -0 -I{} echo {}
)

# Fallback to a known-good ELF so Ghidra always has something valid
if [ "${#PATHS[@]}" -eq 0 ]; then
  [ -x /bin/ls ] && PATHS+=("/bin/ls") || PATHS+=("/usr/bin/ls")
fi

echo "Preloading ${#PATHS[@]} file(s):"
printf '  - %s\n' "${PATHS[@]}"

# ── 1) Start pyghidra-mcp (Streamable HTTP) ─────────────────────────────────
# Note: default bind is 127.0.0.1:8000 for streamable-http. Env FASTMCP_* can
# override in some stacks, but we’ll assume defaults here to avoid surprises.
export FASTMCP_HOST="${FASTMCP_HOST:-127.0.0.1}"
export FASTMCP_PORT="${FASTMCP_PORT:-8000}"
pyghidra-mcp -t streamable-http "${PATHS[@]}" &

# ── 2) Wait for MCP (:8000 by default) ──────────────────────────────────────
for i in {1..60}; do
  python3 - <<'PY' >/dev/null 2>&1 && break
import socket, os, sys
h=os.environ.get("FASTMCP_HOST","127.0.0.1"); p=int(os.environ.get("FASTMCP_PORT","8000"))
s=socket.socket(); s.settimeout(0.25)
try: s.connect((h,p)); sys.exit(0)
except Exception: sys.exit(1)
finally: s.close()
PY
  sleep 0.5
  [ "$i" -eq 60 ] && { echo "ERROR: pyghidra-mcp did not start"; exit 1; }
done
echo "pyghidra-mcp ready on ${FASTMCP_HOST}:${FASTMCP_PORT}"

# ── 3) Run MCPO on :8001 (no conflict) ──────────────────────────────────────
exec mcpo --host "${MCPO_HOST:-0.0.0.0}" --port "${MCPO_PORT:-8001}" --api-key "${MCPO_API_KEY}" \
          --server-type "streamable-http" -- \
          "http://${FASTMCP_HOST}:${FASTMCP_PORT}/mcp"
