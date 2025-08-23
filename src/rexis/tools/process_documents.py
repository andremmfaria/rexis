import hashlib
import json
import mimetypes
import random
import re
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
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

# Typed handle for optional libmagic instance
_MAGIC: Optional[Any] = None

if magic is not None:
    try:
        _MAGIC = magic.Magic(mime=True)
    except Exception:  # pragma: no cover
        _MAGIC = None
else:
    _MAGIC = None


def collect_documents_exec(input_path: Path, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect documents for URLs listed in a JSON file.

    Args:
        input_path: JSON file path whose root is a list of objects containing a 'url' field.
        metadata: Extra metadata merged into each result entry.

    Returns:
        List of result dictionaries for ingestible files (pdf/html/text).
    """
    # 0) Resolve per-run output directories (within the output file path)
    run_root_dir: Path = input_path.resolve().parent / f"{input_path.stem}"
    output_dirs: List[Path] = [
        run_root_dir / "pdf",
        run_root_dir / "html",
        run_root_dir / "text",
        run_root_dir / "files",
    ]
    pdf_dir: Path = output_dirs[0]
    html_dir: Path = output_dirs[1]
    text_dir: Path = output_dirs[2]
    other_dir: Path = output_dirs[3]
    for output_dir in output_dirs:
        output_dir.mkdir(parents=True, exist_ok=True)

    # 1) Load list of entries (dicts with at least 'url')
    url_rows: List[Dict[str, Any]] = _load_input_rows_from_json(input_path)
    if not url_rows:
        LOGGER.warning("No rows found in %s; nothing to download.", input_path)
        return []

    # 2) Prepare URL set (dedupe) and filter social domains
    urls_to_download: List[Tuple[str, Dict[str, Any]]] = []
    normalized_urls_seen: Set[str] = set()
    skipped_social_count: int = 0
    for row in url_rows:
        url: str = str(row.get("url") or "").strip()
        if not url:
            continue
        normalized_url_key: str = normalize_url_key(url)
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

    # 3) Download (parallel with 4 threads, random 1-5s jitter before each request)
    results: List[Dict[str, Any]] = []
    total_to_download: int = len(urls_to_download)
    processed_count: int = 0
    results_lock: threading.Lock = threading.Lock()
    print(f"Starting downloads: {total_to_download} item(s) with up to 4 parallel workers")
    start_ts: float = time.time()
    _print_progress(processed_count, total_to_download, start_ts)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures: List[Future[None]] = [
            executor.submit(
                _download_and_store_url_content,
                url,
                row,
                pdf_dir,
                html_dir,
                text_dir,
                other_dir,
                metadata,
                results,
                results_lock,
            )
            for url, row in urls_to_download
        ]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                # Error already logged inside; keep a summary here
                LOGGER.error("Download task failed: %s", e)
            finally:
                processed_count += 1
                _print_progress(processed_count, total_to_download, start_ts)

    # 4) Write run manifest on disk
    try:
        manifest_path = run_root_dir / f"results-{input_path.stem}.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"Saved collection manifest: {manifest_path}")
    except Exception as e:
        LOGGER.error("Failed to write manifest for %s: %s", input_path, e)

    return results


def _load_input_rows_from_json(path: Path) -> List[Dict[str, Any]]:
    """Load a list of row dictionaries from a JSON file.

    Returns an empty list if the file is missing or the JSON root is not a list.
    """
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


def _is_social_media_url(url_str: str) -> bool:
    """Return True if the URL belongs to a known social-media domain."""
    try:
        p = urlparse(url_str)
        host: str = p.netloc.lower()
        return any(host == d or host.endswith("." + d) for d in SOCIAL_DOMAINS)
    except Exception:
        return False


def _download_and_store_url_content(
    url: str,
    row: Dict[str, Any],
    pdf_dir: Path,
    html_dir: Path,
    text_dir: Path,
    other_dir: Path,
    extra_meta: Dict[str, Any],
    results: List[Dict[str, Any]],
    results_lock: Optional[threading.Lock] = None,
) -> None:
    """Download the URL and persist content; record ingestible results.

    Applies a random 1–5 second jitter before the request and retries transient errors.
    """
    # Random jitter before making the request to avoid burst traffic
    try:
        time.sleep(random.uniform(1.0, 5.0))
    except Exception:
        pass
    # Guess by URL, then GET and sniff first bytes. Avoid extra HEAD round-trip.
    url_file_type_guess: str = _guess_file_type_from_url(url)

    session: requests.Session = requests.Session()
    max_attempts: int = 3
    backoff_seconds: float = 1.5
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
                final_url_after_get: str = str(response.url)
                response_headers: Dict[str, str] = response.headers or {}
                content_type_header: Optional[str] = (
                    response_headers.get("Content-Type") or ""
                ).split(";", 1)[0].strip().lower() or None
                content_disposition: Optional[str] = (
                    response_headers.get("Content-Disposition") or None
                )
                content_disposition_filename: Optional[str] = (
                    _extract_filename_from_content_disposition(content_disposition)
                )

                # Read first chunk for magic detection
                iter_stream: Iterable[bytes] = response.iter_content(chunk_size=65536)
                first_chunk: bytes = b""
                try:
                    first_chunk = next(iter_stream)
                except StopIteration:
                    first_chunk = b""

                magic_mime_type: Optional[str] = _detect_mime_type_with_magic(first_chunk)

                # Classify
                file_type: str = _classify_file_type(
                    content_type_header, magic_mime_type, url_file_type_guess
                )

                # Build filename and suffix
                base_filename: str = _sanitize_filename_from_url(
                    content_disposition_filename or final_url_after_get or url
                )
                file_extension: str = _choose_file_extension(
                    file_type,
                    content_type_header,
                    magic_mime_type,
                    content_disposition_filename,
                    final_url_after_get or url,
                )

                target_dir: Path = {
                    "pdf": pdf_dir,
                    "html": html_dir,
                    "text": text_dir,
                    "other": other_dir,
                }[file_type]
                target_path: Path = target_dir / f"{base_filename}{file_extension}"

                metadata_entry: Dict[str, Any] = {
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
                        if results_lock:
                            with results_lock:
                                results.append(
                                    {
                                        "file_type": file_type,
                                        "file_path": str(target_path),
                                        "metadata": metadata_entry,
                                    }
                                )
                        else:
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
                    if results_lock:
                        with results_lock:
                            results.append(
                                {
                                    "file_type": file_type,
                                    "file_path": str(target_path),
                                    "metadata": metadata_entry,
                                }
                            )
                    else:
                        results.append(
                            {
                                "file_type": file_type,
                                "file_path": str(target_path),
                                "metadata": metadata_entry,
                            }
                        )
                return

        except Exception as exc:
            LOGGER.error("Error downloading %s: %s", url, exc)
            last_exception = exc
            if attempt_index < max_attempts - 1:
                sleep_for_seconds: float = backoff_seconds
                LOGGER.info("Retrying %s in %.1fs due to error: %s", url, sleep_for_seconds, exc)
                time.sleep(sleep_for_seconds)
                backoff_seconds *= 2
                continue
            else:
                raise
    if last_exception:
        raise last_exception


def _guess_file_type_from_url(url_str: str) -> str:
    """Infer a coarse file type from the URL path extension."""
    path: str = urlparse(url_str).path.lower()
    if path.endswith(".pdf"):
        return "pdf"
    if path.endswith((".htm", ".html")):
        return "html"
    if path.endswith(".txt"):
        return "text"
    # Common office docs -> other (we don't ingest these yet)
    if path.endswith((".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".odt", ".rtf")):
        return "other"
    return "unknown"


def _classify_file_type(ctype: Optional[str], magic_mime: Optional[str], guess: str) -> str:
    """Classify into pdf/html/text/other using magic, headers, and URL guess.
    Rules:
      - If magic or header says PDF -> pdf
      - If magic/header says text/plain -> text
      - If magic/header says HTML -> html
      - If URL guess says office doc -> other
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


def _derive_extension_for_type(file_type: str, ctype: Optional[str], url: str) -> str:
    """Choose an extension based on classified type, header, or URL."""
    if file_type == "pdf":
        return ".pdf"
    if file_type == "html":
        return ".html"
    if file_type == "text":
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
    file_type: str,
    ctype: Optional[str],
    magic_mime: Optional[str],
    cd_filename: Optional[str],
    url: str,
) -> str:
    # 1) If Content-Disposition filename has an extension, prefer it
    if cd_filename:
        cd_ext = Path(cd_filename).suffix
        if cd_ext:
            return cd_ext
    # 2) Choose by type directly
    if file_type == "pdf":
        return ".pdf"
    if file_type == "html":
        return ".html"
    if file_type == "text":
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
    """Use libmagic (if available) to detect MIME type from initial bytes."""
    if not first_chunk:
        return None
    if _MAGIC is None:
        return None
    try:
        return _MAGIC.from_buffer(first_chunk)  # e.g., 'application/pdf', 'text/html', 'text/plain'
    except Exception:
        return None


def _extract_filename_from_content_disposition(cd: Optional[str]) -> Optional[str]:
    """Extract a filename from a Content-Disposition header when present."""
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


def _sanitize_filename_from_url(url_str: str) -> str:
    """Build a safe, bounded-length filename from a URL."""
    p = urlparse(url_str)
    raw: str = (p.netloc + p.path).strip("/") or "file"
    # replace separators and unsafe chars
    name: str = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
    # limit length
    if len(name) > 160:
        # keep start and hash tail to avoid collisions
        h: str = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
        name = name[:120] + "_" + h
    return name or "file"


def _print_progress(done: int, total: int, start_ts: float) -> None:
    """Render a simple single-line progress bar with ETA.

    Safe for repeated calls; writes to stdout with carriage return.
    """
    try:
        total = max(total, 1)
        pct = min(max(done / total, 0.0), 1.0)
        bar_len = 28
        filled = int(bar_len * pct)
        bar = "#" * filled + "-" * (bar_len - filled)
        elapsed = max(time.time() - start_ts, 1e-6)
        rate = done / elapsed
        remaining = max(total - done, 0)
        eta = remaining / rate if rate > 0 else 0.0
        sys.stdout.write(
            f"\r[{bar}] {done}/{total} ({pct*100:5.1f}%) | {rate:0.2f}/s | ETA: {eta:0.0f}s\n"
        )
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    except Exception:
        # Avoid breaking main flow on progress rendering issues
        pass
