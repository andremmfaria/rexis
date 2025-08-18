import hashlib
import json
import mimetypes
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from rexis.utils.config import config

# libmagic is optional; fall back if not present on the system
try:
    import magic  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    magic = None
import requests
from rexis.operations.collect.malpedia import normalize_url_key
from rexis.utils.constants import SOCIAL_DOMAINS
from rexis.utils.utils import LOGGER

if magic is not None:
    try:
        _MAGIC = magic.Magic(mime=True)
    except Exception:  # pragma: no cover
        _MAGIC = None
else:
    _MAGIC = None


def collect_documents_exec(input_path: Path, metadata: dict) -> List[Dict[str, Any]]:
    # 0) Resolve per-run output directories (within the output file path)
    run_root_dir: Path = input_path.resolve().parent / f"{input_path.stem}"
    output_dirs = [
        run_root_dir / "pdf",
        run_root_dir / "html",
        run_root_dir / "text",
        run_root_dir / "files",
    ]
    pdf_dir, html_dir, text_dir, other_dir = output_dirs
    for output_dir in output_dirs:
        output_dir.mkdir(parents=True, exist_ok=True)

    # 1) Load list of entries (dicts with at least 'url')
    url_rows: List[Dict] = _load_input_rows_from_json(input_path)
    if not url_rows:
        LOGGER.warning("No rows found in %s; nothing to download.", input_path)
        return []

    # 2) Prepare URL set (dedupe) and filter social domains
    urls_to_download: List[Tuple[str, Dict]] = []
    normalized_urls_seen: set = set()
    skipped_social_count = 0
    for row in url_rows:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        normalized_url_key = normalize_url_key(url)
        if normalized_url_key in normalized_urls_seen:
            continue
        if _is_social_media_url(normalized_url_key):
            skipped_social_count += 1
            continue
        normalized_urls_seen.add(normalized_url_key)
        urls_to_download.append((url, row))

    if skipped_social_count:
        print(f"Skipped {skipped_social_count} social-media URLs.")
        print(f"Prepared {len(urls_to_download)} unique URL(s) to download.")

    # 3) Download
    results: List[Dict[str, Any]] = []
    total_to_download = len(urls_to_download)
    processed_count = 0
    print(f"Starting downloads: {total_to_download} item(s)")
    for url, row in urls_to_download:
        try:
            _download_and_store_url_content(
                url=url,
                row=row,
                pdf_dir=pdf_dir,
                html_dir=html_dir,
                text_dir=text_dir,
                other_dir=other_dir,
                extra_meta=metadata,
                results=results,
            )
        except Exception as e:
            LOGGER.warning("Failed to download %s: %s", url, e)
        finally:
            processed_count += 1
            print(f"Progress: {processed_count}/{total_to_download} documents processed")

    # 4) Write run manifest on disk
    try:
        manifest_path = run_root_dir / f"results-{input_path.stem}.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Saved collection manifest: {manifest_path}")
    except Exception as e:
        LOGGER.warning("Failed to write manifest for %s: %s", input_path, e)

    return results


def _load_input_rows_from_json(path: Path) -> List[Dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            # Ensure list of dicts
            return [x for x in data if isinstance(x, dict)]
        LOGGER.warning("Unexpected JSON root in %s (type=%s)", path, type(data))
        return []
    except FileNotFoundError:
        LOGGER.error("Input path not found: %s", path)
        return []
    except Exception as e:
        LOGGER.error("Failed to read %s: %s", path, e)
        return []


def _is_social_media_url(u: str) -> bool:
    try:
        p = urlparse(u)
        host = p.netloc.lower()
        return any(host == d or host.endswith("." + d) for d in SOCIAL_DOMAINS)
    except Exception:
        return False


def _download_and_store_url_content(
    url: str,
    row: Dict,
    pdf_dir: Path,
    html_dir: Path,
    text_dir: Path,
    other_dir: Path,
    extra_meta: Dict,
    results: List[Dict[str, Any]],
) -> None:
    # Guess by URL, then GET and sniff first bytes. Avoid extra HEAD round-trip.
    url_file_type_guess = _guess_file_type_from_url(url)

    session = requests.Session()
    max_attempts = 3
    backoff_seconds = 1.0
    last_exception: Optional[Exception] = None

    for attempt_index in range(max_attempts):
        try:
            print(f"GET {url} (stream) ...")
            with session.get(
                url,
                headers={
                    "User-Agent": config.ingestion.default_user_agent,
                    "Accept": "*/*",
                },
                stream=True,
                timeout=(15, 120),
            ) as response:
                # Handle transient HTTP status codes manually for retry
                if response.status_code in (429, 500, 502, 503, 504):
                    raise requests.HTTPError(f"HTTP {response.status_code}")

                response.raise_for_status()
                final_url_after_get = str(response.url)
                response_headers = response.headers or {}
                content_type_header = (response_headers.get("Content-Type") or "").split(";", 1)[
                    0
                ].strip().lower() or None
                content_disposition = response_headers.get("Content-Disposition") or None
                content_disposition_filename = _extract_filename_from_content_disposition(
                    content_disposition
                )

                # Read first chunk for magic detection
                iter_stream = response.iter_content(chunk_size=65536)
                first_chunk = b""
                try:
                    first_chunk = next(iter_stream)
                except StopIteration:
                    first_chunk = b""

                magic_mime_type = _detect_mime_type_with_magic(first_chunk)

                # Classify
                file_type = _classify_file_type(
                    content_type_header, magic_mime_type, url_file_type_guess
                )

                # Build filename and suffix
                base_filename = _sanitize_filename_from_url(
                    content_disposition_filename or final_url_after_get or url
                )
                file_extension = _choose_file_extension(
                    file_type,
                    content_type_header,
                    magic_mime_type,
                    content_disposition_filename,
                    final_url_after_get or url,
                )

                target_dir = {
                    "pdf": pdf_dir,
                    "html": html_dir,
                    "text": text_dir,
                    "other": other_dir,
                }[file_type]
                target_path = target_dir / f"{base_filename}{file_extension}"

                metadata_entry = {
                    "source_url": url,
                    "resolved_url_head": None,
                    "resolved_url_get": final_url_after_get or url,
                    "content_type_head": None,
                    "content_type_get": content_type_header,
                    "content_disposition_filename": content_disposition_filename,
                    "magic_mime": magic_mime_type,
                    "chosen_type": file_type,
                    "families": row.get("families") or [],
                    "actors": row.get("actors") or [],
                    "title": row.get("title") or "",
                    "date": row.get("date") or "",
                    "source": row.get("source") or "",
                    **(row.get("meta") or {}),
                    **(extra_meta or {}),
                }

                if target_path.exists():
                    LOGGER.debug("Already exists, skipping: %s", target_path)
                    if file_type in ("pdf", "html", "text"):
                        results.append(
                            {
                                "file_type": file_type,
                                "file_path": str(target_path),
                                "metadata": metadata_entry,
                            }
                        )
                    return

                print(f"Writing -> {target_path} ({file_type})")
                with open(target_path, "wb") as f:
                    if first_chunk:
                        f.write(first_chunk)
                    for chunk in iter_stream:
                        if chunk:
                            f.write(chunk)

                # Append result for ingestion (only for supported types)
                if file_type in ("pdf", "html", "text"):
                    results.append(
                        {
                            "file_type": file_type,
                            "file_path": str(target_path),
                            "metadata": metadata_entry,
                        }
                    )
                return

        except Exception as exc:
            last_exception = exc
            if attempt_index < max_attempts - 1:
                sleep_for_seconds = backoff_seconds
                LOGGER.info("Retrying %s in %.1fs due to error: %s", url, sleep_for_seconds, exc)
                time.sleep(sleep_for_seconds)
                backoff_seconds *= 2
                continue
            else:
                raise
    if last_exception:
        raise last_exception


def _guess_file_type_from_url(u: str) -> str:
    path = urlparse(u).path.lower()
    if path.endswith(".pdf"):
        return "pdf"
    if path.endswith((".htm", ".html")):
        return "html"
    if path.endswith(".txt"):
        return "text"
    # Common office docs → other (we don't ingest these yet)
    if path.endswith((".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".odt", ".rtf")):
        return "other"
    return "unknown"


def _classify_file_type(ctype: Optional[str], magic_mime: Optional[str], guess: str) -> str:
    """Classify into pdf/html/text/other using magic, headers, and URL guess.
    Rules:
      - If magic or header says PDF → pdf
      - If magic/header says text/plain → text
      - If magic/header says HTML → html
      - If URL guess says office doc → other
      - Else default to html (per requirement)
    """

    def is_pdf(m: Optional[str]) -> bool:
        return bool(m) and m.lower().startswith("application/pdf")

    def is_html(m: Optional[str]) -> bool:
        if not m:
            return False
        m = m.lower()
        return m.startswith("text/html") or m.startswith("application/xhtml")

    def is_text(m: Optional[str]) -> bool:
        return bool(m) and m.lower().startswith("text/plain")

    if is_pdf(magic_mime) or is_pdf(ctype):
        return "pdf"
    if is_text(magic_mime) or is_text(ctype):
        return "text"
    if is_html(magic_mime) or is_html(ctype):
        return "html"
    if guess == "other":
        return "other"
    return "html"


def _derive_extension_for_type(typ: str, ctype: Optional[str], url: str) -> str:
    if typ == "pdf":
        return ".pdf"
    if typ == "html":
        return ".html"
    if typ == "text":
        return ".txt"
    path = urlparse(url).path
    ext = Path(path).suffix
    if ext:
        return ext
    if ctype:
        m = mimetypes.guess_extension(ctype)
        if m:
            return m
    return ""


def _choose_file_extension(
    typ: str, ctype: Optional[str], magic_mime: Optional[str], cd_filename: Optional[str], url: str
) -> str:
    # 1) If Content-Disposition filename has an extension, prefer it
    if cd_filename:
        cd_ext = Path(cd_filename).suffix
        if cd_ext:
            return cd_ext
    # 2) Choose by type directly
    if typ == "pdf":
        return ".pdf"
    if typ == "html":
        return ".html"
    if typ == "text":
        return ".txt"
    # 3) Try magic or header mime mapping
    for m in (magic_mime, ctype):
        if m:
            ext = mimetypes.guess_extension(m)
            if ext:
                return ext
    # 4) Fallback to URL-derived ext
    return _derive_extension_for_type("other", ctype, url)


def _detect_mime_type_with_magic(first_chunk: bytes) -> Optional[str]:
    if not first_chunk:
        return None
    if _MAGIC is None:
        return None
    try:
        return _MAGIC.from_buffer(first_chunk)  # e.g., 'application/pdf', 'text/html', 'text/plain'
    except Exception:
        return None


def _extract_filename_from_content_disposition(cd: Optional[str]) -> Optional[str]:
    if not cd:
        return None
    # RFC5987/6266 handling can be complex; cover common cases.
    try:
        # filename*=UTF-8''encoded or filename="..."
        m = re.search(r"filename\*=UTF-8''([^;]+)", cd, re.IGNORECASE)
        if m:
            from urllib.parse import unquote

            return unquote(m.group(1))
        m = re.search(r'filename\s*=\s*"([^"\\]+)"', cd, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"filename\s*=\s*([^;]+)", cd, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    except Exception:
        return None
    return None


def _sanitize_filename_from_url(u: str) -> str:
    p = urlparse(u)
    raw = (p.netloc + p.path).strip("/") or "file"
    # replace separators and unsafe chars
    name = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
    # limit length
    if len(name) > 160:
        # keep start and hash tail to avoid collisions
        h = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
        name = name[:120] + "_" + h
    return name or "file"
