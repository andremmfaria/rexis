import json
import pathlib
import re
from datetime import date, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
import typer
from dateutil import parser as dtparse
from fuzzywuzzy import fuzz
from rexis.utils.config import config
from rexis.utils.utils import LOGGER

MALPEDIA_BASE = config.ingestion.malpedia_base_url.rstrip("/")
REFS_ENDPOINT = f"{MALPEDIA_BASE}/api/get/references"
BIB_ENDPOINT = f"{MALPEDIA_BASE}/api/get/bib"


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
    params = {
        "family_id": family_id,
        "actor_id": actor_id,
        "search_term": search_term,
        "start_date": start_date,
        "end_date": end_date,
        "max_items": max_items,
        "output_path": output_path,
    }
    params_str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
    print(f"Starting collect_malpedia_exec with params: {params_str}")

    # If the user provided a start date but no end date, set end date to today and inform the user.
    if start_date and not end_date:
        end_date = date.today().isoformat()
        msg = f"[date] --start-date set without --end-date. Using end={end_date} (today)."
        print(msg)

    # 1) fetch sources
    print("Fetching references index from Malpedia API.")
    refs_index: Dict[str, List[Dict[str, Any]]] = fetch_references_index()
    print("Fetching BibTeX dump from Malpedia API.")
    bib_text: str = fetch_bibtex_dump()

    bib_refs: List[Dict[str, Any]] = parse_bibtex_entries(bib_text)

    # 2) join
    print("Cross-referencing BibTeX entries with references index.")
    merged: List[Dict[str, Any]] = cross_reference(refs_index, bib_refs)
    LOGGER.info(f"[merge] merged entries: {len(merged)}")

    # 3) AND filters
    print("Applying AND filters to merged entries.")
    filtered: List[Dict[str, Any]] = filter_and_semantics(
        rows=merged,
        family_id=family_id,
        actor_id=actor_id,
        search_term=search_term,
        start_date=start_date,
        end_date=end_date,
        max_items=max_items,
    )
    LOGGER.info(f"[filter] after AND filters: {len(filtered)}")

    # 4) save
    print(f"Saving filtered entries to {output_path}")
    saved: int = save_json(filtered, output_path)
    print(f"Saved {saved} entries to {output_path}")
    return saved


def _headers() -> Dict[str, str]:
    return {
        "User-Agent": "rexis-malpedia/1.0 (+research; RAG build)",
        "Accept": "*/*",
    }


def fetch_references_index() -> Dict[str, List[Dict[str, Any]]]:
    """
    GET /api/get/references → { url: [ {type,id,common_name,alt_names,url}, ... ], ... }
    """
    print(f"[GET] {REFS_ENDPOINT}")
    try:
        r = requests.get(REFS_ENDPOINT, headers=_headers(), timeout=60)
        r.raise_for_status()
        data: Dict[str, Dict[str, List[Any]]] = r.json().get("references", "")
        if not isinstance(data, Dict):
            LOGGER.error("Unexpected /api/get/references response type: %s", type(data))
            raise RuntimeError("Unexpected /api/get/references response")
        print(f"[refs] loaded {len(data)} URL keys")
        return data
    except Exception as e:
        LOGGER.error(f"Failed to fetch references index: {e}")
        raise


def fetch_bibtex_dump() -> str:
    """
    GET /api/get/bib → BibTeX of all references
    """
    print(f"[GET] {BIB_ENDPOINT}")
    try:
        r = requests.get(BIB_ENDPOINT, timeout=90)
        r.raise_for_status()
        LOGGER.info(f"[bibtex] size={len(r.text)} bytes")
        return r.text
    except Exception as e:
        LOGGER.error(f"Failed to fetch BibTeX dump: {e}")
        raise


def _strip_braces(val: str) -> str:
    v = val.strip()
    if v.startswith("{"):
        v = v[1:]
    if v.endswith("}"):
        v = v[:-1]
    result = v.strip()
    LOGGER.debug(f"Stripped braces: '{val}' -> '{result}'")
    return result


def parse_bibtex_entries(bibtex_text: str) -> List[Dict[str, Any]]:
    """
    Minimal parser for @online{...} entries we see in Malpedia’s dump.
    Produces dicts with (title, url, source, date, meta{author,language,urldate,...})
    """
    entries = re.split(r"@online\s*{", bibtex_text, flags=re.IGNORECASE)[1:]
    out: List[Dict[str, Any]] = []
    print(f"Parsing {len(entries)} BibTeX entries.")

    for entry in entries:
        fields = dict(
            (k.lower(), _strip_braces(v))
            for k, v in re.findall(r'(\w+)\s*=\s*[{{"]([^}}"]+)[}}"]', entry, flags=re.IGNORECASE)
        )
        title = fields.get("title", "")
        url = (fields.get("url", "") or "").strip()
        source = (
            fields.get("organization", "")
            or fields.get("publisher", "")
            or fields.get("journal", "")
            or fields.get("venue", "")
            or (urlparse(url).netloc if url else "")
        )
        date_str = fields.get("date", "") or fields.get("year", "") or fields.get("published", "")
        meta = {
            "author": fields.get("author", ""),
            "language": fields.get("language", ""),
            "urldate": fields.get("urldate", ""),
        }
        # keep any extra unknown fields
        for k, v in fields.items():
            if k not in {
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
                meta[k] = v

        if url:
            out.append(
                {
                    "title": title,
                    "url": url,
                    "source": source,
                    "date": date_str,
                    "meta": meta,
                }
            )
        else:
            LOGGER.warning(f"BibTeX entry missing URL: {fields}")

    print(f"Parsed {len(out)} BibTeX entries with URLs.")
    return dedupe_by_url(out)


def dedupe_by_url(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for it in items:
        u = (it.get("url") or "").strip()
        if not u or u in seen:
            LOGGER.debug(f"Duplicate or empty URL skipped: {u}")
            continue
        seen.add(u)
        out.append(it)
    print(f"Deduplicated to {len(out)} unique URLs.")
    return out


def normalize_url_key(u: str) -> str:
    """
    Normalize URL for cross-ref:
    - strip whitespace
    - lower scheme/host (netloc)
    - remove trailing slash
    """
    u = (u or "").strip()
    try:
        p = urlparse(u)
        netloc = p.netloc.lower()
        scheme = (p.scheme or "http").lower()
        path = p.path.rstrip("/") or "/"
        norm = f"{scheme}://{netloc}{path}"
        if p.query:
            norm += f"?{p.query}"
        return norm
    except Exception as e:
        LOGGER.warning(f"Failed to normalize URL '{u}': {e}")
        return u.rstrip("/")


def concat_common_name_with_alts(common_name: str, alts: List[str]) -> str:
    alts = [a for a in (alts or []) if a]
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
        u_norm = normalize_url_key(ref["url"])
        entities = mapping.get(u_norm, [])
        fams: List[Dict[str, str]] = []
        acts: List[Dict[str, str]] = []
        for e in entities:
            typ = e.get("type")
            cid = e.get("id")
            cname = e.get("common_name") or ""
            alts = e.get("alt_names") or []
            label = concat_common_name_with_alts(cname, alts)
            if typ == "family":
                fams.append({"id": cid, "common_name": label})
            elif typ == "actor":
                acts.append({"id": cid, "common_name": label})

        merged.append(
            {
                "title": ref.get("title", ""),
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "date": ref.get("date", ""),
                "families": fams,
                "actors": acts,
                "meta": ref.get("meta", {}),
            }
        )
    LOGGER.info(f"Cross-referenced {len(merged)} BibTeX entries.")
    return merged


def parse_any_date(s: Optional[str]) -> Optional[date]:
    if not s:
        LOGGER.debug("No date string provided to parse_any_date.")
        return None
    try:
        dt = dtparse.parse(s)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        result = dt.date()
        LOGGER.debug(f"Parsed date string '{s}' -> {result}")
        return result
    except Exception as e:
        LOGGER.warning(f"Failed to parse date string '{s}': {e}")
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
    sdate = parse_any_date(start_date) if start_date else None
    edate = parse_any_date(end_date) if end_date else None

    params = {
        "family_id": family_id,
        "actor_id": actor_id,
        "search_term": search_term,
        "start_date": start_date,
        "end_date": end_date,
        "max_items": max_items,
    }
    params_str = ", ".join(f"{k}={v}" for k, v in params.items() if v is not None)
    print(f"Filtering {len(rows)} rows" + (f" with {params_str}" if params_str else ""))

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
            vals = []
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

        vals = all_searchable_strings(r)
        # Try regex match first, fallback to fuzzy if regex fails or doesn't match
        if pattern:
            if any(pattern.search(n) for n in vals):
                return True
        # fallback to fuzzywuzzy partial ratio
        needle = search_term.lower()
        return any(fuzz.partial_ratio(needle, n.lower()) >= 85 for n in vals)

    def matches_date(r: Dict[str, Any]) -> bool:
        # If neither start nor end → keep all (no date filter)
        if not (sdate or edate):
            return True
        d = parse_any_date(r.get("date"))
        if sdate and (not d or d < sdate):
            return False
        if edate and (not d or d > edate):
            return False
        return True

    out = [
        r
        for r in rows
        if matches_family(r) and matches_actor(r) and matches_search(r) and matches_date(r)
    ]
    if max_items and max_items > 0:
        out = out[:max_items]
    LOGGER.info(f"Filtered down from search patternto {len(out)} rows.")
    return out


def save_json(rows: List[Dict[str, Any]], path: pathlib.Path) -> int:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        LOGGER.info(f"Successfully saved {len(rows)} rows to {path}")
        return len(rows)
    except Exception as e:
        LOGGER.error(f"Failed to save JSON to {path}: {e}")
        raise
