#!/usr/bin/env bash
# Unpack PE malware sample zips directly into the category's "decompressed" folder (no per-zip subdir)
# Example:
#   ./samples/botnet/AAAA.zip       -> ./samples/botnet/decompressed/...
#   ./samples/ransomware/BBBB.zip   -> ./samples/ransomware/decompressed/...

set -uo pipefail
# Enable NO_NOMATCH only when running under zsh
if [ -n "${ZSH_VERSION:-}" ]; then
  setopt NO_NOMATCH
fi

############# CONFIG #############
SAMPLES_ROOT="./samples"     # root of your structure
OUT_SUBDIR="decompressed"    # name of the output folder inside each category
ZIP_PASSWORD="infected"      # set "" if zips are not password-protected
OVERWRITE=0                  # 0: never overwrite, 1: force overwrite
QUIET=1                      # 1: quieter unzip logs, 0: verbose

# ---- require 7z ----
if command -v 7z >/dev/null 2>&1; then
  EXTRACT_TOOL="7z"
else
  echo "[ERROR] Need '7z' installed." >&2
  exit 1
fi

[[ -d "$SAMPLES_ROOT" ]] || { echo "[ERROR] Not found: $SAMPLES_ROOT" >&2; exit 1; }

processed=0
ok=0
fail=0

# Use find to safely handle any filenames
while IFS= read -r -d '' zipf; do
  ((processed++))
  dir="$(dirname "$zipf")"
  base="$(basename "$zipf")"
  name="${base%.zip}"
  outdir="${dir}/${OUT_SUBDIR}"

  mkdir -p "$outdir" || { echo "[ERROR] mkdir failed: $outdir"; ((fail++)); continue; }

  echo "[*] Extracting: $zipf -> $outdir"

  # 7z behaves slightly differently
  # -aos: skip existing files; -aoa: overwrite all
  ao_flag=$([[ $OVERWRITE -eq 1 ]] && echo "-aoa" || echo "-aos")
  # Quiet flags for 7z (disable stdout, stderr and progress)
  quiet_flag=$([[ $QUIET -eq 1 ]] && echo "-bso0 -bse0 -bsp0" || echo "")
  if [[ -n "$ZIP_PASSWORD" ]]; then
    7z x "$zipf" -p"$ZIP_PASSWORD" -o"$outdir" $ao_flag $quiet_flag >/dev/null 2>&1
  else
    7z x "$zipf" -o"$outdir" $ao_flag $quiet_flag >/dev/null 2>&1
  fi
  rc=$?

  if [[ $rc -eq 0 ]]; then
    ((ok++))
  else
    echo "[WARN] Extraction failed (rc=$rc): $zipf"
    ((fail++))
  fi
done < <(find "$SAMPLES_ROOT" -type f -name '*.zip' -print0)

echo
echo "Summary"
echo "-------"
echo "Tool       : $EXTRACT_TOOL"
echo "Root       : $SAMPLES_ROOT"
echo "Output tag : $OUT_SUBDIR"
echo "Password   : ${ZIP_PASSWORD:-<none>}"
echo "Processed  : $processed"
echo "Succeeded  : $ok"
echo "Failed     : $fail"

# Safety reminder
echo
echo "[note] Extracted files are malware samples — handle in a sandbox, never execute on a host you care about."
