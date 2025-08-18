#!/usr/bin/env bash
# Install Temurin (Adoptium) Java 21 from x64 binaries under /opt/java-temurin
# (without touching system alternatives) and Ghidra 11.4.1 under /opt/ghidra.
# Also wire GHIDRA_INSTALL_DIR and GHIDRA_JAVA_HOME in your shell RC. Safe to rerun.
# Requires sudo for system steps.

set -euo pipefail

# ── Config (edit if you like) ────────────────────────────────────────────────
GHIDRA_VERSION="11.4.1"
GHIDRA_DATE="20250731"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
GHIDRA_DIR="/opt/ghidra" # Final install dir should be exactly this path
# If you want checksum verification, paste the SHA256 (from the release page) into GHIDRA_SHA256:
GHIDRA_SHA256="${GHIDRA_SHA256:-}" # e.g. "59b6...d07ea0  ghidra.zip"

# Temurin download (latest GA JDK 21 x64 HotSpot from Adoptium API)
TEMURIN_MAJOR="21"
# Adoptium API returns a tar.gz binary for linux/x64 JDK 21 HotSpot
TEMURIN_API_URL="https://api.adoptium.net/v3/binary/latest/${TEMURIN_MAJOR}/ga/linux/x64/jdk/hotspot/normal/eclipse"
TEMURIN_DIR="/opt/java-temurin"
TEMURIN_SYMLINK="${TEMURIN_DIR}/current"  # Stable path we’ll point GHIDRA_JAVA_HOME to
# Optional: set TEMURIN_SHA256 env var to verify the downloaded tarball
TEMURIN_SHA256="${TEMURIN_SHA256:-}"

# Choose which RC file to write to
SHELL_NAME="$(basename "${SHELL:-}")"
RC_FILE="$HOME/.bashrc"; [ "$SHELL_NAME" = "zsh" ] && RC_FILE="$HOME/.zshrc"

say()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[✗]\033[0m %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_java_home() {
  # Prefer JAVA_HOME if valid
  if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    echo "${JAVA_HOME}"; return
  fi
  # Resolve from `java` on PATH
  local jbin jreal jhome
  jbin=$(command -v java 2>/dev/null || true)
  if [ -n "$jbin" ]; then
    jreal=$(readlink -f "$jbin" 2>/dev/null || echo "$jbin")
    jhome=$(dirname "$(dirname "$jreal")")
    [ -x "${jhome}/bin/java" ] && echo "$jhome" && return
  fi
  # Common local Temurin install
  if [ -x "${TEMURIN_SYMLINK}/bin/java" ]; then
    dirname "${TEMURIN_SYMLINK}/bin/java" | xargs dirname
    return
  fi
  # Common Temurin path on Ubuntu/Debian (amd64)
  [ -x "/usr/lib/jvm/temurin-21-jdk-amd64/bin/java" ] && echo "/usr/lib/jvm/temurin-21-jdk-amd64" && return
  # Fallback: empty
  echo ""
}

# Prefer a Temurin 21 installation path if present
find_temurin_java_home() {
  # Prefer our local tarball install under /opt/java-temurin
  if [ -x "${TEMURIN_SYMLINK}/bin/java" ]; then
    echo "${TEMURIN_SYMLINK}"; return 0
  fi
  for p in "${TEMURIN_DIR}"/jdk*/bin/java; do
    [ -x "$p" ] && dirname "$(dirname "$p")" && return 0
  done
  # Debian/Ubuntu and multi-arch patterns
  for p in /usr/lib/jvm/temurin-21-jdk*/bin/java; do
    [ -x "$p" ] && dirname "$(dirname "$p")" && return 0
  done
  # Fedora/RPM variants sometimes install under /usr/lib/jvm with arch suffixes
  for p in /usr/lib/jvm/temurin-21-jdk*/bin/java; do
    [ -x "$p" ] && dirname "$(dirname "$p")" && return 0
  done
  echo ""
}

install_temurin_from_tarball() {
  # Skip if already installed unless FORCE_JAVA_INSTALL=1
  if [ -x "${TEMURIN_SYMLINK}/bin/java" ] && [ "${FORCE_JAVA_INSTALL:-0}" != "1" ]; then
    say "Temurin JDK appears installed at ${TEMURIN_SYMLINK} — skipping download."
    return 0
  fi

  say "Installing Temurin ${TEMURIN_MAJOR} (linux x64 tarball) → ${TEMURIN_DIR}"
  sudo mkdir -p "${TEMURIN_DIR}"

  # Try to ensure tools exist (best-effort on Debian/Ubuntu)
  sudo apt-get update >/dev/null 2>&1 || true
  sudo apt-get install -y wget tar >/dev/null 2>&1 || true
  have wget || err "wget is required"
  have tar || err "tar is required"

  local tmp
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  ( cd "$tmp" && wget -O temurin.tar.gz "${TEMURIN_API_URL}" )

  if [ -n "${TEMURIN_SHA256}" ]; then
    say "Verifying Temurin checksum…"
    ( cd "$tmp" && echo "${TEMURIN_SHA256}" | sha256sum -c - ) || err "Temurin checksum verification failed"
  else
    warn "Skipping Temurin checksum verification (set TEMURIN_SHA256 to enable)."
  fi

  ( cd "$tmp" && tar -xzf temurin.tar.gz )
  local extracted
  extracted="$(find "$tmp" -maxdepth 1 -type d -name 'jdk-*' | head -n1)"
  [ -d "$extracted" ] || err "Could not find extracted Temurin JDK directory"

  local dest
  dest="${TEMURIN_DIR}/$(basename "$extracted")"
  # If same version exists, replace it atomically
  if [ -d "$dest" ]; then
    local ts
    ts="$(date +%Y%m%d%H%M%S)"
    say "Backing up existing ${dest} → ${dest}.bak-${ts}"
    sudo mv "$dest" "${dest}.bak-${ts}"
  fi
  sudo rm -rf "$dest"
  sudo mv "$extracted" "$dest"

  # Update stable symlink
  if [ -L "${TEMURIN_SYMLINK}" ] || [ -e "${TEMURIN_SYMLINK}" ]; then
    sudo rm -rf "${TEMURIN_SYMLINK}"
  fi
  sudo ln -s "$dest" "${TEMURIN_SYMLINK}"
}

# ── Install Ghidra 11.4.1 ────────────────────────────────────────────────────
install_ghidra() {
  say "Installing Ghidra ${GHIDRA_VERSION} → ${GHIDRA_DIR}"
  sudo mkdir -p "$(dirname "${GHIDRA_DIR}")"
  sudo apt-get update >/dev/null 2>&1 || true
  sudo apt-get install -y unzip wget >/dev/null 2>&1 || true

  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  ( cd "$tmp" && wget -O ghidra.zip "${GHIDRA_URL}" )

  if [ -n "$GHIDRA_SHA256" ]; then
    say "Verifying checksum…"
    ( cd "$tmp" && echo "${GHIDRA_SHA256}" | sha256sum -c - ) || err "Checksum verification failed"
  else
    warn "Skipping checksum verification (set GHIDRA_SHA256 to enable)."
  fi

  ( cd "$tmp" && unzip -q ghidra.zip )
  local extracted
  extracted="$(find "$tmp" -maxdepth 1 -type d -name "ghidra_*_PUBLIC" | head -n1)"
  [ -d "$extracted" ] || err "Could not find extracted Ghidra directory"

  # Backup any existing install, then replace atomically
  if [ -d "${GHIDRA_DIR}" ]; then
    local ts
    ts="$(date +%Y%m%d%H%M%S)"
    say "Backing up existing ${GHIDRA_DIR} → ${GHIDRA_DIR}.bak-${ts}"
    sudo mv "${GHIDRA_DIR}" "${GHIDRA_DIR}.bak-${ts}"
  fi
  sudo rm -rf "${GHIDRA_DIR}"
  sudo mv "$extracted" "${GHIDRA_DIR}"
}

# ── Env wiring ───────────────────────────────────────────────────────────────
ensure_env() {
  # Point GHIDRA_INSTALL_DIR to /opt/ghidra (where we renamed the extracted dir)
  [ -d "${GHIDRA_DIR}" ] || err "Expected Ghidra dir not found: ${GHIDRA_DIR}"
  grep -q 'GHIDRA_INSTALL_DIR' "${RC_FILE}" 2>/dev/null || {
    say "Adding GHIDRA env to ${RC_FILE}"
    {
      echo "export GHIDRA_INSTALL_DIR=${GHIDRA_DIR}"
      echo 'export PATH="$PATH:$GHIDRA_INSTALL_DIR/support"'
    } >> "${RC_FILE}"
  }
  export GHIDRA_INSTALL_DIR="${GHIDRA_DIR}"
  export PATH="$PATH:$GHIDRA_INSTALL_DIR/support"

  # Prefer GHIDRA_JAVA_HOME over JAVA_HOME for ghidraRun
  touch "${RC_FILE}"
  local JHOME_T JHOME
  JHOME_T="$(find_temurin_java_home)"
  if [ -z "$JHOME_T" ]; then
    JHOME="$(detect_java_home)"
  else
    JHOME="$JHOME_T"
  fi
  if [ -n "$JHOME" ]; then
    # Replace any existing GHIDRA_JAVA_HOME line to point to Temurin
    if grep -q '^export GHIDRA_JAVA_HOME=' "${RC_FILE}" 2>/dev/null; then
      sed -i.bak "s|^export GHIDRA_JAVA_HOME=.*$|export GHIDRA_JAVA_HOME=${JHOME}|" "${RC_FILE}"
    else
      echo "export GHIDRA_JAVA_HOME=${JHOME}" >> "${RC_FILE}"
    fi
    export GHIDRA_JAVA_HOME="${JHOME}"
  else
    warn "Could not auto-detect Temurin JAVA_HOME — ghidraRun may prompt for a JDK once."
  fi
}

# ── Verify ───────────────────────────────────────────────────────────────────
verify() {
  say "Verifying install…"
  if [ -f "${GHIDRA_DIR}/Ghidra/application.properties" ]; then
    ver="$(grep -E '^application\.version=' "${GHIDRA_DIR}/Ghidra/application.properties" | cut -d'=' -f2)"
    say "Ghidra version: ${ver}"
  fi
  # Try a quick non-interactive call (avoid hanging the terminal)
  if command -v timeout >/dev/null 2>&1; then
    timeout 5s "${GHIDRA_DIR}/support/analyzeHeadless" -version >/dev/null 2>&1 || true
    timeout 5s "${GHIDRA_DIR}/ghidraRun" -h >/dev/null 2>&1 || true
  fi
  say "Done. Open a new shell or 'source ${RC_FILE}' to load env vars."
}

# ── Run ──────────────────────────────────────────────────────────────────────
install_temurin_from_tarball
[ -d "${GHIDRA_DIR}" ] || install_ghidra
ensure_env
verify
