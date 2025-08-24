#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Configuration (edit or export)
# -------------------------
MB_API_URL="${MB_API_URL:-https://mb-api.abuse.ch/api/v1/}"
# space-separated list of tags; each tag is processed independently
MB_TAGS="${MB_TAGS:-trojan ransomware botnet rootkit}"
# download up to this many per tag (random)
MB_SAMPLE_COUNT="${MB_SAMPLE_COUNT:-5}"
MB_LIMIT="${MB_LIMIT:-500}"
# optional API key for MalwareBazaar (set via env: MB_API_KEY)
MB_API_KEY="${MB_API_KEY:-}"
# curl/network settings
MB_TIMEOUT="${MB_TIMEOUT:-20}"          # seconds
MB_RETRIES="${MB_RETRIES:-4}"          # total attempts per request
MB_RETRY_DELAY="${MB_RETRY_DELAY:-2}"  # seconds between retries

# -------------------------
# Requirements
# -------------------------
for cmd in curl jq shuf; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Error: '$cmd' is required but not found in PATH." >&2
    exit 1
  }
done

# -------------------------
# Helpers
# -------------------------
b64dec() {
  if base64 --help 2>&1 | grep -qi "gnu coreutils"; then base64 -d; else base64 -D; fi
}

mb_post() {
  # usage: mb_post key=val key=val ...
  # prints body to stdout, returns curl exit status (0 on success)
  # retries with simple backoff
  local attempt=0
  local body=""
  # common headers for JSON API calls
  local headers=(
    -H "Accept: application/json"
    -H "Content-Type: application/x-www-form-urlencoded"
    -H "Auth-Key: $MB_API_KEY"
  )
  while (( attempt < MB_RETRIES )); do
    attempt=$((attempt+1))
    # shellcheck disable=SC2086
    body="$(curl -sS -m "$MB_TIMEOUT" \
      "${headers[@]}" \
      -X POST \
      ${@:1} \
      "$MB_API_URL" || true)"
    # If looks like JSON and jq can parse, return it
    if [[ "${body}" =~ ^\{ ]]; then
      if echo "$body" | jq . >/dev/null 2>&1; then
        printf '%s' "$body"
        return 0
      fi
    fi
    # If not valid JSON, maybe 429/HTML; show snippet on final failure
    if (( attempt < MB_RETRIES )); then
      sleep "$MB_RETRY_DELAY"
    else
      printf '%s' "$body"
      return 0
    fi
  done
}

looks_like_json() {
  [[ "$1" =~ ^\{ ]] && echo "$1" | jq . >/dev/null 2>&1
}

is_zip_file() {
  # no 'file' dependency — check first byte isn't '{' (JSON)
  head -c1 "$1" | grep -q '{' && return 1 || return 0
}

# -------------------------
# Main
# -------------------------
for TAG in ${MB_TAGS}; do
  OUTDIR="${TAG}"
  mkdir -p "$OUTDIR"
  echo "==> Querying MalwareBazaar for tag: '$TAG' (include: '$TAG' + 'exe'; exclude other input tags)"

  # Query tag info
  RAW_JSON_PATH="${OUTDIR}/tag_${TAG}_response.json"
  RESP="$(mb_post --data-urlencode "query=get_taginfo" --data-urlencode "tag=${TAG}" --data-urlencode "limit=${MB_LIMIT}")"

  if ! looks_like_json "$RESP"; then
    echo "   ! Non-JSON response for tag '$TAG'. Saving snippet and skipping."
    printf '%s' "$RESP" > "${RAW_JSON_PATH}.raw"
    head -c 300 "${RAW_JSON_PATH}.raw" | sed 's/[^[:print:]\t]//g' | sed 's/$/\n/' >&2
    continue
  fi

  printf '%s' "$RESP" | jq '.' > "$RAW_JSON_PATH"
  STATUS=$(jq -r '.query_status // empty' < "$RAW_JSON_PATH")

  if [[ -z "$STATUS" || "$STATUS" == "no_taginfo" || "$STATUS" == "error" ]]; then
    echo "   ! API query_status='${STATUS:-<empty>}' for '$TAG'. Skipping."
    continue
  fi

  # Filter rules (case-insensitive):
  #  - must include current TAG
  #  - must include 'exe'
  #  - must NOT include any other tags listed in MB_TAGS (except the current TAG)
  mapfile -t PICKED_B64 < <(
    jq -r --arg tag "$TAG" --arg mbtags "$MB_TAGS" '
      .data
      | map(
          select(
            (.tags | type=="array") and (
              ([ .tags[] | ascii_downcase ]) as $ltags |
              ($tag | ascii_downcase) as $q |
              ($mbtags | ascii_downcase | gsub("\\s+";" ") | split(" ") | map(select(length>0))) as $in_tags |
              # contains current tag and exe
              ($ltags | index($q)) != null and
              ($ltags | index("exe")) != null and
              # no overlap with other input tags
              ([ $in_tags[] | select(. != $q) ] ) as $others |
              ( $ltags | map(select(. as $t | ($others | index($t)) != null)) | length ) == 0
            )
          )
        )
      | .[]
      | @base64
    ' "$RAW_JSON_PATH" | shuf -n "$MB_SAMPLE_COUNT"
  )

  if [[ ${#PICKED_B64[@]} -eq 0 ]]; then
    echo "   ! No samples found with ONLY '${TAG}' + 'exe'."
    continue
  fi

  echo "   -> Selected ${#PICKED_B64[@]} sample(s) for '${TAG}'."

  # Download each selected sample
  for B64 in "${PICKED_B64[@]}"; do
    OBJ_JSON="$(printf '%s' "$B64" | b64dec)"
    SHA256="$(printf '%s' "$OBJ_JSON" | jq -r '.sha256_hash // empty')"

    if [[ -z "$SHA256" ]]; then
      echo "      ! Skipping entry without sha256_hash."
      continue
    fi

    META_JSON="${OUTDIR}/${SHA256}.json"
    ZIP_PATH="${OUTDIR}/${SHA256}.zip"
    printf '%s\n' "$OBJ_JSON" | jq '.' > "$META_JSON"

    echo "      -> Downloading $SHA256"
    TMP_OUT="$(mktemp)"
    # Download (ZIP or JSON error)
    {
      # build headers for file download
      curl -sS -m "$MB_TIMEOUT" \
        -H "Accept: application/octet-stream" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Auth-Key: $MB_API_KEY" \
        -X POST \
        --data-urlencode "query=get_file" \
        --data-urlencode "sha256_hash=${SHA256}" \
        -o "$TMP_OUT" \
        "$MB_API_URL"
    }

    if head -c1 "$TMP_OUT" | grep -q '{'; then
      echo "        ! API returned JSON instead of ZIP for $SHA256. Saving as .error.json"
      if ! jq '.' "$TMP_OUT" > "${ZIP_PATH}.error.json"; then
        mv "$TMP_OUT" "${ZIP_PATH}.error.json"
      else
        rm -f "$TMP_OUT"
      fi
      continue
    fi

    mv "$TMP_OUT" "$ZIP_PATH"
    echo "        ✓ Saved ${ZIP_PATH} (ZIP password: infected)"
    sleep 1
  done

  echo "==> Finished tag: '$TAG'"
done

echo "All done."
