# Install Ghidra + PyGhidra on Linux (Local)

These steps set up **Ghidra** (NSA’s reverse-engineering suite), **Java 21**, and the env vars PyGhidra expects so local REXIS commands can analyze binaries without Docker.

> Tested on Ubuntu/Debian and Fedora. Adjust paths as needed.

## Quick install (script)

Use the helper script for a repeatable install that doesn’t touch system Java alternatives:

- Path: `scripts/install-ghidra.sh`
- What it does:
	- Installs Temurin JDK 21 from Adoptium tarball under `/opt/java-temurin/<jdk…>` and a stable symlink at `/opt/java-temurin/current`.
	- Downloads Ghidra 11.4.1 and installs it to `/opt/ghidra` (so `ghidraRun` is at `/opt/ghidra/ghidraRun`).
	- Adds env vars to your shell rc: `GHIDRA_INSTALL_DIR=/opt/ghidra`, `PATH+=:$GHIDRA_INSTALL_DIR/support`, and `GHIDRA_JAVA_HOME=/opt/java-temurin/current` (or detected JDK21).
	- Skips checksum verification unless you set `GHIDRA_SHA256`/`TEMURIN_SHA256` env vars.
	- Safe to rerun. It won’t overwrite an existing `/opt/ghidra` unless you remove it first.
- It chooses `~/.zshrc` if your shell is zsh, else `~/.bashrc`.

```bash
chmod +x scripts/install-ghidra.sh
sudo ./scripts/install-ghidra.sh
# Reload your shell rc (zsh shown; use ~/.bashrc if you use bash):
source ~/.zshrc
```

Advanced: you can pass optional env vars when running the script, e.g.

```bash
sudo GHIDRA_SHA256="<sha256>  ghidra.zip" \
		 TEMURIN_SHA256="<sha256>  temurin.tar.gz" \
		 FORCE_JAVA_INSTALL=1 \
		 ./scripts/install-ghidra.sh
```

Then verify:

```bash
/opt/ghidra/support/analyzeHeadless -version
/opt/ghidra/ghidraRun -h | head -n 3
```

Or follow the manual steps below.

## 1) Install Java 21 (required by Ghidra ≥ 11.2)

Pick one of the options below.

### Option A: Use distro OpenJDK 21

Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk
java -version   # should show 21.x (OpenJDK)
```

Fedora
```bash
sudo dnf install -y java-21-openjdk java-21-openjdk-devel
java -version
```

After installing, set `GHIDRA_JAVA_HOME` to that JDK (helps Ghidra pick the right Java):
```bash
# For zsh; use ~/.bashrc if you use bash
echo 'export GHIDRA_JAVA_HOME=$(dirname $(dirname $(readlink -f $(command -v java))))' >> ~/.zshrc
source ~/.zshrc
```

### Option B: Temurin 21 under /opt (matches the script)

```bash
sudo mkdir -p /opt/java-temurin
cd /tmp
wget -O temurin.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
# Optional checksum:
# echo "<sha256>  temurin.tar.gz" | sha256sum -c -
tar -xzf temurin.tar.gz
sudo mv ./jdk-* /opt/java-temurin/
sudo ln -sfn /opt/java-temurin/jdk-* /opt/java-temurin/current

# Point Ghidra to this JDK
echo 'export GHIDRA_JAVA_HOME=/opt/java-temurin/current' >> ~/.zshrc
source ~/.zshrc
```

## 2) Download and install Ghidra to /opt/ghidra

Example uses **11.4.1**. Check NSA releases for newer versions:

• https://github.com/NationalSecurityAgency/ghidra/releases

```bash
sudo rm -rf /opt/ghidra
sudo mkdir -p /opt
sudo apt-get install -y unzip wget || true

cd /tmp
wget -O ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.1_build/ghidra_11.4.1_PUBLIC_20250731.zip"

# Optional: verify checksum from the release page
# echo "<sha256>  ghidra.zip" | sha256sum -c -

unzip -q ghidra.zip
sudo rm -rf /opt/ghidra
sudo mv ghidra_*_PUBLIC /opt/ghidra

ls -1 /opt/ghidra | head
```

## 3) Set environment variables (used by PyGhidra and CLI helpers)

```bash
# Adjust rc file to your shell (~/.zshrc shown)
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.zshrc
echo 'export PATH="$PATH:$GHIDRA_INSTALL_DIR/support"' >> ~/.zshrc
# If you didn’t set it earlier, point Ghidra to a Java 21 home:
# echo 'export GHIDRA_JAVA_HOME=/opt/java-temurin/current' >> ~/.zshrc
source ~/.zshrc

# Quick check
analyzeHeadless -version || true
ghidraRun -h | head -n 3 || true
```

## Notes

- The script installs Temurin and Ghidra under `/opt` and does not change system Java alternatives.
- It updates only your shell rc (`~/.zshrc` for zsh, otherwise `~/.bashrc`). Open a new shell or `source` the file to load the vars.
- To reinstall Ghidra with the script, remove `/opt/ghidra` first; the script skips reinstall if that directory already exists.
- Optional env vars honored by the script: `GHIDRA_SHA256`, `TEMURIN_SHA256`, `FORCE_JAVA_INSTALL=1`.
