import json
import pathlib
import re
import time
from datetime import date, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
from dateutil import parser as dtparse
from fuzzywuzzy import fuzz
from rexis.utils.config import config
from rexis.utils.utils import LOGGER, get_version

MALPEDIA_BASE: str = config.ingestion.malpedia_base_url.rstrip("/")
REFS_ENDPOINT: str = f"{MALPEDIA_BASE}/api/get/references"
BIB_ENDPOINT: str = f"{MALPEDIA_BASE}/api/get/bib"


def collect_malpedia_exec(
    family_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    search_term: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    max_items: Optional[int] = None,
    output_path: pathlib.Path = pathlib.Path("malpedia_urls.json"),
) -> int:
    """
    Cross-reference Malpedia references:
      - /api/get/references (URL -> families/actors)
      - /api/get/bib (BibTeX of all references)
    Output a JSON file with merged entries including families/actors arrays.
    All flags apply with AND semantics.
    """
    start_ts = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))

    # Derive run directory and base name from output_path (e.g., malpedia-collect-<run>.json)
    base_path: str = output_path.stem
    run_dir: pathlib.Path = output_path.parent / base_path
    run_dir.mkdir(parents=True, exist_ok=True)

    params: Dict[str, Any] = {
        "family_id": family_id,
        "actor_id": actor_id,
        "search_term": search_term,
        "start_date": start_date,
        "end_date": end_date,
        "max_items": max_items,
        "output_path": output_path,
    }
    params_str: str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
    print(f"[collect-mp] Starting collect_malpedia_exec with params: {params_str}")

    status: str = "success"
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = {
        "refs_index_url_keys": None,
        "bib_entries_total": None,
        "merged_entries": None,
        "filtered_entries": None,
        "saved_entries": None,
    }
    saved: int = 0

    try:
        # If the user provided a start date but no end date, set end date to today and inform the user.
        if start_date and not end_date:
            end_date = date.today().isoformat()
            print(
                f"[collect-mp] --start-date set without --end-date. Using end={end_date} (today)."
            )

        # 1) fetch sources
        print("[collect-mp] Fetching references index from Malpedia API.")
        refs_index: Dict[str, List[Dict[str, Any]]] = fetch_references_index()
        metrics["refs_index_url_keys"] = len(refs_index)
        print("[collect-mp] Fetching BibTeX dump from Malpedia API.")
        bib_text: str = fetch_bibtex_dump()

        bib_refs: List[Dict[str, Any]] = parse_bibtex_entries(bib_text)
        metrics["bib_entries_total"] = len(bib_refs)

        # 2) join
        print("[collect-mp] Cross-referencing BibTeX entries with references index.")
        merged: List[Dict[str, Any]] = cross_reference(refs_index, bib_refs)
        metrics["merged_entries"] = len(merged)
        LOGGER.info(f"[merge] merged entries: {len(merged)}")

        # 3) AND filters
        print("[collect-mp] Applying AND filters to merged entries.")
        filtered: List[Dict[str, Any]] = filter_and_semantics(
            rows=merged,
            family_id=family_id,
            actor_id=actor_id,
            search_term=search_term,
            start_date=start_date,
            end_date=end_date,
            max_items=max_items,
        )
        metrics["filtered_entries"] = len(filtered)
        LOGGER.info(f"[filter] after AND filters: {len(filtered)}")

        # 4) save
        print(f"[collect-mp] Saving filtered entries to {output_path}")
        saved = save_json(filtered, output_path)
        metrics["saved_entries"] = saved
        print(f"[collect-mp] Saved {saved} entries to {output_path}")
    except Exception as e:
        LOGGER.error("Malpedia collection failed: %s", e)
        status = "error"
        error_message = str(e)
        exc = e
    else:
        exc = None
    finally:
        end_ts = time.time()
        ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts))
        duration_sec = round(end_ts - start_ts, 3)
        print(f"[collect-mp] Preparing run report (status={status}, duration={duration_sec}s)...")
        report: Dict[str, Any] = {
            "run_id": base_path,
            "base_path": base_path,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration_sec,
            "status": status,
            "error": error_message,
            "summary": metrics,
            "inputs": {
                "family_id": family_id,
                "actor_id": actor_id,
                "search_term": search_term,
                "start_date": start_date,
                "end_date": end_date,
                "max_items": max_items,
            },
            "outputs": {
                "output_path": str(output_path),
                "run_dir": str(run_dir),
            },
            "environment": {
                "rexis_version": get_version(),
                "malpedia_base_url": MALPEDIA_BASE,
            },
        }
        report_path: pathlib.Path = run_dir / f"{base_path}.report.json"
        try:
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            LOGGER.info(f"Run report written to {report_path}")
        except Exception as rexc:
            LOGGER.error("Failed to write run report %s: %s", report_path, rexc)

    if exc:
        raise exc

    return saved


def fetch_references_index() -> Dict[str, List[Dict[str, Any]]]:
    """
    Retrieve the references index from Malpedia.

    Returns:
        Dict[str, List[Dict[str, Any]]]: Mapping of URL (string) to a list of entity dicts
        where each entity describes either a family or an actor with fields like
        'type', 'id', 'common_name', and 'alt_names'.
    """
    print(f"[collect-mp] [GET] {REFS_ENDPOINT}")
    try:
        response = requests.get(
            REFS_ENDPOINT,
            headers={
                "User-Agent": "rexis-malpedia/1.0 (+research; RAG build)",
                "Accept": "*/*",
            },
            timeout=60,
        )
        response.raise_for_status()
        json_payload: Dict[str, Any] = response.json()
        data: Dict[str, List[Dict[str, Any]]] = json_payload.get("references", {})  # type: ignore[assignment]
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected /api/get/references response type: {type(data)}")
        print(f"[collect-mp] Loaded {len(data)} URL keys")
        return data
    except Exception as e:
        LOGGER.error(f"Failed to fetch references index: {e}")
        raise


def fetch_bibtex_dump() -> str:
    """
    Retrieve the complete BibTeX dump from Malpedia.

    Returns:
        str: Raw BibTeX text containing multiple @online entries.
    """
    print(f"[collect-mp] [GET] {BIB_ENDPOINT}")
    try:
        response = requests.get(BIB_ENDPOINT, timeout=90)
        response.raise_for_status()
        LOGGER.info(f"[bibtex] size={len(response.text)} bytes")
        return response.text
    except Exception as e:
        LOGGER.error(f"Failed to fetch BibTeX dump: {e}")
        raise


def _strip_braces(value: str) -> str:
    """Strip one leading and trailing brace from a BibTeX value, if present.

    Args:
        value: The raw string potentially wrapped with braces.

    Returns:
        A cleaned string without the outermost braces.
    """
    working: str = value.strip()
    if working.startswith("{"):
        working = working[1:]
    if working.endswith("}"):
        working = working[:-1]
    result: str = working.strip()
    LOGGER.debug(f"Stripped braces: '{value}' -> '{result}'")
    return result


def parse_bibtex_entries(bibtex_text: str) -> List[Dict[str, Any]]:
    """
    Parse @online BibTeX entries from Malpedia's dump.

    Args:
        bibtex_text: Raw BibTeX text containing multiple @online entries.

    Returns:
        List[Dict[str, Any]]: Deduplicated list of reference dicts, each containing
        'title', 'url', 'source', 'date', and 'meta'.
    """
    raw_entries: List[str] = re.split(r"@online\s*{", bibtex_text, flags=re.IGNORECASE)[1:]
    parsed_entries: List[Dict[str, Any]] = []
    print(f"[collect-mp] Parsing {len(raw_entries)} BibTeX entries.")

    for entry in raw_entries:
        field_map: Dict[str, str] = dict(
            (k.lower(), _strip_braces(v))
            for k, v in re.findall(r'(\w+)\s*=\s*[{{"]([^}}"]+)[}}"]', entry, flags=re.IGNORECASE)
        )
        title: str = field_map.get("title", "")
        url_value: str = (field_map.get("url", "") or "").strip()
        source: str = (
            field_map.get("organization", "")
            or field_map.get("publisher", "")
            or field_map.get("journal", "")
            or field_map.get("venue", "")
            or (urlparse(url_value).netloc if url_value else "")
        )
        date_str: str = (
            field_map.get("date", "") or field_map.get("year", "") or field_map.get("published", "")
        )
        meta: Dict[str, Any] = {
            "author": field_map.get("author", ""),
            "language": field_map.get("language", ""),
            "urldate": field_map.get("urldate", ""),
        }
        # keep any extra unknown fields
        for key, value in field_map.items():
            if key not in {
                "title",
                "url",
                "organization",
                "publisher",
                "journal",
                "venue",
                "date",
                "year",
                "published",
                "author",
                "language",
                "urldate",
            }:
                meta[key] = value

        if url_value:
            parsed_entries.append(
                {
                    "title": title,
                    "url": url_value,
                    "source": source,
                    "date": date_str,
                    "meta": meta,
                }
            )
        else:
            LOGGER.warning(f"BibTeX entry missing URL: {field_map}")

    print(f"[collect-mp] Parsed {len(parsed_entries)} BibTeX entries with URLs.")
    return dedupe_by_url(parsed_entries)


def dedupe_by_url(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate a list of reference dicts by their 'url' field.

    Args:
        items: List of reference dicts, each expected to have a 'url' key.

    Returns:
        List[Dict[str, Any]]: A new list preserving order with unique URLs only.
    """
    seen_urls: Set[str] = set()
    unique_items: List[Dict[str, Any]] = []
    for item in items:
        url_value: str = (item.get("url") or "").strip()
        if not url_value or url_value in seen_urls:
            LOGGER.debug(f"Duplicate or empty URL skipped: {url_value}")
            continue
        seen_urls.add(url_value)
        unique_items.append(item)
    print(f"[collect-mp] Deduplicated to {len(unique_items)} unique URLs.")
    return unique_items


def normalize_url_key(u: str) -> str:
    """
    Normalize a URL to a canonical key for cross-referencing.

    Steps:
      - Strip surrounding whitespace
      - Lowercase scheme and host (netloc)
      - Remove trailing slash from path (but keep at least '/')
      - Preserve query string if present

    Args:
        u: Input URL string.

    Returns:
        str: Normalized URL string.
    """
    u = (u or "").strip()
    try:
        parsed_url = urlparse(u)
        netloc: str = parsed_url.netloc.lower()
        scheme: str = (parsed_url.scheme or "http").lower()
        path: str = parsed_url.path.rstrip("/") or "/"
        normalized_url: str = f"{scheme}://{netloc}{path}"
        if parsed_url.query:
            normalized_url += f"?{parsed_url.query}"
        return normalized_url
    except Exception as e:
        LOGGER.warning(f"Failed to normalize URL '{u}': {e}")
        return u.rstrip("/")


def concat_common_name_with_alts(common_name: str, alts: List[str]) -> str:
    """Concatenate a common name with its alternative names for display.

    Args:
        common_name: Primary name.
        alts: List of alternative names.

    Returns:
        str: A combined label like "Name (alt1 | alt2)" or just the common_name if no alts.
    """
    alts = [alt for alt in (alts or []) if alt]
    return f"{common_name} ({' | '.join(alts)})" if alts else common_name


def cross_reference(
    refs_index: Dict[str, List[Dict[str, Any]]], bib_refs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Join by URL (normalized). For each bib entry, attach families/actors from refs_index if present.
    """
    # Build lookup with normalized URLs
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    for raw_url, entities in refs_index.items():
        mapping[normalize_url_key(raw_url)] = entities

    merged: List[Dict[str, Any]] = []
    for ref in bib_refs:
        normalized = normalize_url_key(ref["url"])
        entities_for_url: List[Dict[str, Any]] = mapping.get(normalized, [])
        families: List[Dict[str, str]] = []
        actors: List[Dict[str, str]] = []
        for entity in entities_for_url:
            typ: Optional[str] = entity.get("type")
            entity_id: Optional[str] = entity.get("id")
            common_name: str = entity.get("common_name") or ""
            alt_names: List[str] = entity.get("alt_names") or []
            label: str = concat_common_name_with_alts(common_name, alt_names)
            if typ == "family":
                families.append({"id": entity_id, "common_name": label})
            elif typ == "actor":
                actors.append({"id": entity_id, "common_name": label})

        merged.append(
            {
                "title": ref.get("title", ""),
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "date": ref.get("date", ""),
                "families": families,
                "actors": actors,
                "meta": ref.get("meta", {}),
            }
        )
    LOGGER.info(f"Cross-referenced {len(merged)} BibTeX entries.")
    return merged


def parse_any_date(s: Optional[str]) -> Optional[date]:
    """Parse an arbitrary date string to a date object (UTC if no tzinfo).

    Args:
        s: Date string in any common format (ISO 8601 preferred).

    Returns:
        Optional[date]: Parsed date, or None if parsing fails or input is empty.
    """
    if not s:
        LOGGER.debug("No date string provided to parse_any_date.")
        return None
    try:
        dt_value = dtparse.parse(s)
        if not dt_value.tzinfo:
            dt_value = dt_value.replace(tzinfo=timezone.utc)
        result: date = dt_value.date()
        LOGGER.debug(f"Parsed date string '{s}' -> {result}")
        return result
    except Exception as e:
        LOGGER.error(f"Failed to parse date string '{s}': {e}")
        return None


def filter_and_semantics(
    rows: List[Dict[str, Any]],
    family_id: Optional[str],
    actor_id: Optional[str],
    search_term: Optional[str],
    start_date: Optional[str],
    end_date: Optional[str],
    max_items: Optional[int],
) -> List[Dict[str, Any]]:
    start_date_parsed: Optional[date] = parse_any_date(start_date) if start_date else None
    end_date_parsed: Optional[date] = parse_any_date(end_date) if end_date else None

    params: Dict[str, Any] = {
        "family_id": family_id,
        "actor_id": actor_id,
        "search_term": search_term,
        "start_date": start_date,
        "end_date": end_date,
        "max_items": max_items,
    }
    params_str: str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
    print(
        f"[collect-mp] Filtering {len(rows)} rows" + (f" with {params_str}" if params_str else "")
    )

    def matches_family(r: Dict[str, Any]) -> bool:
        if not family_id:
            return True
        pattern = re.compile(family_id, re.IGNORECASE)
        for f in r.get("families") or []:
            # Match against id, common_name, and alt_names
            if pattern.match(f.get("id") or ""):
                return True
            if pattern.match(f.get("common_name") or ""):
                return True
            for alt in f.get("alt_names") or []:
                if pattern.match(alt):
                    return True
        return False

    def matches_actor(r: Dict[str, Any]) -> bool:
        if not actor_id:
            return True
        pattern = re.compile(actor_id, re.IGNORECASE)
        for a in r.get("actors") or []:
            # Match against id, common_name, and alt_names
            if pattern.match(a.get("id") or ""):
                return True
            if pattern.match(a.get("common_name") or ""):
                return True
            for alt in a.get("alt_names") or []:
                if pattern.match(alt):
                    return True
        return False

    def matches_search(r: Dict[str, Any]) -> bool:
        """
        Regex and fuzzy (substring, case-insensitive) search over all metadata fields, including family/actor names, alt names, title, source, url, and meta fields.
        If provided, this must match as part of AND semantics.
        """
        if not search_term:
            return True
        try:
            pattern = re.compile(search_term, re.IGNORECASE)
        except re.error:
            pattern = None

        def all_searchable_strings(row: Dict[str, Any]) -> list:
            vals: List[str] = []
            # Families and actors: id, common_name, alt_names
            for ent in (row.get("families") or []) + (row.get("actors") or []):
                vals.append(ent.get("id") or "")
                vals.append(ent.get("common_name") or "")
                vals.extend(ent.get("alt_names") or [])
            # Top-level fields
            vals.append(row.get("title") or "")
            vals.append(row.get("source") or "")
            vals.append(row.get("url") or "")
            # Meta fields
            meta = row.get("meta") or {}
            for v in meta.values():
                if isinstance(v, str):
                    vals.append(v)
            return vals

        vals: List[str] = all_searchable_strings(r)
        # Try regex match first, fallback to fuzzy if regex fails or doesn't match
        if pattern:
            if any(pattern.search(n) for n in vals):
                return True
        # fallback to fuzzywuzzy partial ratio
        needle: str = search_term.lower()
        return any(fuzz.partial_ratio(needle, n.lower()) >= 85 for n in vals)

    def matches_date(r: Dict[str, Any]) -> bool:
        # If neither start nor end -> keep all (no date filter)
        if not (start_date_parsed or end_date_parsed):
            return True
        d = parse_any_date(r.get("date"))
        if start_date_parsed and (not d or d < start_date_parsed):
            return False
        if end_date_parsed and (not d or d > end_date_parsed):
            return False
        return True

    filtered_rows: List[Dict[str, Any]] = [
        r
        for r in rows
        if matches_family(r) and matches_actor(r) and matches_search(r) and matches_date(r)
    ]
    if max_items and max_items > 0:
        filtered_rows = filtered_rows[:max_items]
    LOGGER.info(f"Filtered down from search pattern to {len(filtered_rows)} rows.")
    return filtered_rows


def save_json(rows: List[Dict[str, Any]], path: pathlib.Path) -> int:
    """Persist rows as pretty-printed JSON to the given path.

    Args:
        rows: The list of reference dicts to save.
        path: Output filesystem path.

    Returns:
        int: Number of rows written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        LOGGER.info(f"Successfully saved {len(rows)} rows to {path}")
        return len(rows)
    except Exception as e:
        LOGGER.error(f"Failed to save JSON to {path}: {e}")
        raise
