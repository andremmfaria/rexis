# Install Ghidra + PyGhidra on Linux (Local)

These steps set up **Ghidra** (NSA’s reverse-engineering suite), **Java 21**, and **PyGhidra** so your local REXIS commands can analyze binaries without Docker.

> Tested on Ubuntu/Debian and Fedora. Adjust paths as needed.

## Quick install (script)

Prefer an automated setup? Use the helper script in this repo:

- Path: `scripts/install-ghidra.sh`
- It automates the steps below (installing Java 21, fetching Ghidra to `/opt/ghidra`, and wiring PyGhidra).
- Run it with sufficient privileges if installing under `/opt`.

```bash
chmod +x scripts/install-ghidra.sh
sudo ./scripts/install-ghidra.sh
# If the script updates your shell rc, reload it (e.g., for zsh):
source ~/.zshrc
```

Or follow the manual steps below.

## 1) Install Java 21 (required by Ghidra ≥ 11.2)

### Ubuntu / Debian (Temurin 21)
```bash
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk
java -version   # should show 21.x (OpenJDK)
````

### Fedora

```bash
sudo dnf install -y java-21-openjdk java-21-openjdk-devel
java -version
```

## 2) Download and unpack Ghidra (into /opt/ghidra directly)

Pick a version (example uses **11.4.1**). Check NSA’s releases if you want another:

* [https://github.com/NationalSecurityAgency/ghidra/releases](https://github.com/NationalSecurityAgency/ghidra/releases)

```bash
sudo rm -rf /opt/ghidra
sudo mkdir -p /opt/ghidra
sudo apt-get install -y unzip || true

# Download (update the URL if you choose another version)
cd /tmp
sudo wget -O ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.1_build/ghidra_11.4.1_PUBLIC_20250731.zip"

# (Optional) Verify checksum — paste the SHA256 from the release page:
# echo "<SHA256>  ghidra.zip" | sha256sum -c -*

# Unzip to /tmp, then move the contents into /opt/ghidra so that /opt/ghidra is the install root
sudo unzip -q /tmp/ghidra.zip -d /tmp
sudo mv /tmp/ghidra_*_PUBLIC/* /opt/ghidra/
sudo rmdir /tmp/ghidra_*_PUBLIC
sudo rm -f /tmp/ghidra.zip

ls -1 /opt/ghidra
```

## 3) Set environment variables (for PyGhidra)

```bash
# Set Ghidra install to /opt/ghidra (adjust your shell rc: ~/.zshrc or ~/.bashrc)
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.zshrc
echo 'export PATH="$PATH:$GHIDRA_INSTALL_DIR/support"' >> ~/.zshrc
source ~/.zshrc
```
