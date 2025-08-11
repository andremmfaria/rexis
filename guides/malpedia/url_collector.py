import argparse
import csv
import json
import logging
import os
import pathlib
import random
import re
import time
from typing import Any, Dict, List, Optional, Union

import requests

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de"
API = f"{MALPEDIA_BASE}/api"


def build_auth_headers(api_key: Optional[str]) -> Dict[str, str]:
    logging.debug(f"Preparing auth headers. API key provided: {'Yes' if api_key else 'No'}")
    headers = {
        "User-Agent": "rexis-malpedia/1.0 (+research; RAG build)",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"apikey {api_key}"
    return headers


def malpedia_api_get(session: requests.Session, url: str, **kw) -> Dict[str, Any]:
    """Perform a GET request to the Malpedia API and return JSON or raw text."""
    logging.info(f"GET {url}")
    response = session.get(url, timeout=30, **kw)
    response.raise_for_status()
    logging.debug(f"Response status: {response.status_code}")
    try:
        return response.json()
    except Exception:
        # If not JSON, return raw text for further handling (e.g., BibTeX)
        logging.warning(f"Non-JSON response from {url}, returning raw text.")
        return {"_raw_text": response.text}


def normalize_reference(ref: dict) -> dict:
    result = dict(ref)
    result["title"] = (
        result.get("title")
        or result.get("name")
        or result.get("paper_title")
        or result.get("reference_title")
        or ""
    )
    result["source"] = (
        result.get("source")
        or result.get("publisher")
        or result.get("journal")
        or result.get("venue")
        or ""
    )
    result["date"] = (
        result.get("date")
        or result.get("year")
        or result.get("published")
        or result.get("publication_date")
        or ""
    )
    meta = {
        k: v
        for k, v in result.items()
        if k not in {"title", "url", "source", "date", "tags", "meta"}
    }
    if isinstance(result.get("meta"), dict):
        meta.update(result["meta"])
    result["meta"] = meta
    return result


def collect_malpedia_references(
    api_key: Optional[str] = None,
    family_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    search_term: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Returns a list of reference dicts: {title, url, source, date, tags?, ...}
    Tries specific endpoints first, then falls back to global references.
    """
    # List to accumulate all found references
    references: List[Dict[str, Any]] = []
    logging.info(
        f"Collecting references (family_id={family_id}, actor_id={actor_id}, search={search_term})"
    )
    # Random delay between requests to avoid hammering the API
    rate_delay = random.uniform(1, 5)

    with requests.Session() as session:
        session.headers.update(build_auth_headers(api_key))

        # Specific bibliography by family/actor if provided
        # Fetch references for a specific malware family if provided
        if family_id:
            logging.info(f"Fetching bibliography for family_id: {family_id}")
            data = malpedia_api_get(session, f"{API}/get/bib/family/{family_id}")
            references.extend([normalize_reference(ref) for ref in (data.get("result", []) or [])])
            time.sleep(rate_delay)

        # Fetch references for a specific threat actor if provided
        if actor_id:
            logging.info(f"Fetching bibliography for actor_id: {actor_id}")
            data = malpedia_api_get(session, f"{API}/get/bib/actor/{actor_id}")
            references.extend([normalize_reference(ref) for ref in (data.get("result", []) or [])])
            time.sleep(rate_delay)

        # Search helpers if you only have a keyword/name
        # If a search term is provided, search for matching families and actors
        if search_term:
            logging.info(f"Searching for family and actor matches for: {search_term}")
            family_search_response = malpedia_api_get(
                session, f"{API}/find/family/{requests.utils.quote(search_term)}"
            )
            if isinstance(family_search_response, dict):
                family_matches = family_search_response.get("result", []) or []
            elif isinstance(family_search_response, list):
                family_matches = family_search_response
            else:
                family_matches = []

            actor_search_response = malpedia_api_get(
                session, f"{API}/find/actor/{requests.utils.quote(search_term)}"
            )
            if isinstance(actor_search_response, dict):
                actor_matches = actor_search_response.get("result", []) or []
            elif isinstance(actor_search_response, list):
                actor_matches = actor_search_response
            else:
                actor_matches = []
            time.sleep(rate_delay)

            # For each matching family, fetch its bibliography
            for family in family_matches[:10]:  # be polite
                family_id_candidate = (
                    family.get("id")
                    or family.get("family_id")
                    or family.get("value")
                    or family.get("name")
                )
                if not family_id_candidate:
                    continue
                logging.info(
                    f"Fetching bibliography for family search match: {family_id_candidate}"
                )
                data = malpedia_api_get(session, f"{API}/get/bib/family/{family_id_candidate}")
                # Handle BibTeX (non-JSON) response
                if "_raw_text" in data:
                    logging.info(f"Parsing BibTeX references from {family_id_candidate}")
                    references.extend(
                        [normalize_reference(ref) for ref in parse_bibtex_urls(data["_raw_text"])]
                    )
                else:
                    references.extend(
                        [normalize_reference(ref) for ref in (data.get("result", []) or [])]
                    )
                time.sleep(rate_delay)

            # For each matching actor, fetch its bibliography
            for actor in actor_matches[:10]:
                actor_id_candidate = (
                    actor.get("id")
                    or actor.get("actor_id")
                    or actor.get("value")
                    or actor.get("name")
                )
                if not actor_id_candidate:
                    continue
                logging.info(f"Fetching bibliography for actor search match: {actor_id_candidate}")
                data = malpedia_api_get(session, f"{API}/get/bib/actor/{actor_id_candidate}")
                if "_raw_text" in data:
                    logging.info(f"Parsing BibTeX references from {actor_id_candidate}")
                    references.extend(
                        [normalize_reference(ref) for ref in parse_bibtex_urls(data["_raw_text"])]
                    )
                else:
                    references.extend(
                        [normalize_reference(ref) for ref in (data.get("result", []) or [])]
                    )
                time.sleep(rate_delay)

        if not references:
            logging.info("No specific references found, fetching global references index.")
            data = malpedia_api_get(session, f"{API}/get/references")
            references.extend([normalize_reference(ref) for ref in (data.get("result", []) or [])])
            time.sleep(rate_delay)

        return references


def parse_bibtex_urls(bibtex_text: str) -> List[Dict[str, Any]]:
    entries = re.split(r"@online\s*{", bibtex_text)[1:]
    refs = []

    def strip_braces(val: str) -> str:
        val = val.strip()
        if val.startswith("{"): val = val[1:]
        if val.endswith("}"): val = val[:-1]
        return val.strip()

    for entry in entries:
        fields = dict(
            (k, strip_braces(v))
            for k, v in re.findall(r"(\w+)\s*=\s*[{{\"]([^}}\"]+)[}}\"]", entry)
        )
        ref = {
            "title": strip_braces(fields.get("title", "")),
            "url": strip_braces(fields.get("url", "")),
            "source": strip_braces(fields.get("organization", "")),
            "date": strip_braces(fields.get("date", "")),
            "meta": {
                k: strip_braces(v)
                for k, v in fields.items()
                if k not in {"title", "url", "organization", "date"}
            },
        }
        if ref["url"]:
            refs.append(ref)
    seen = set()
    unique_refs = []
    for ref in refs:
        url = ref["url"]
        if url in seen:
            continue
        seen.add(url)
        unique_refs.append(ref)
    logging.info(f"Collected {len(unique_refs)} unique references from BibTeX.")
    return unique_refs


def save_url_list_to_file(
    reference_list: List[Dict[str, Any]], output_path: Union[str, os.PathLike], fmt: str = "json"
) -> int:
    """
    Save a list of reference dicts to a file.
    If fmt == 'json', output a single JSON list with all metadata.
    If fmt == 'csv', output a CSV file with columns for all metadata fields.
    Returns the number of entries saved.
    """

    file_path: pathlib.Path = pathlib.Path(output_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not reference_list or not isinstance(reference_list, List):
        logging.error("No references to save or input is not a list.")
        return 0
    # Filter only valid dicts with a URL
    filtered_refs: List[Dict[str, Any]] = [
        ref for ref in reference_list if ref and isinstance(ref, dict) and ref.get("url")
    ]
    if fmt == "json":
        file_path.write_text(
            json.dumps(filtered_refs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        logging.info(f"Saved {len(filtered_refs)} JSON objects to {output_path}")
        return len(filtered_refs)
    elif fmt == "csv":
        # Collect all possible keys for columns
        all_keys = set()
        for ref in filtered_refs:
            all_keys.update(ref.keys())
        # Flatten meta dict if present
        for ref in filtered_refs:
            if "meta" in ref and isinstance(ref["meta"], dict):
                for k, v in ref["meta"].items():
                    ref[f"meta.{k}"] = v
                del ref["meta"]
        # Update columns after flattening
        all_keys = set()
        for ref in filtered_refs:
            all_keys.update(ref.keys())
        columns = sorted(all_keys)
        with file_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            count = 0
            for ref in filtered_refs:
                writer.writerow(ref)
                count += 1
        logging.info(f"Saved {count} rows to {output_path} (CSV)")
        return count
    else:
        raise ValueError(f"Unsupported format: {fmt}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect Malpedia references and save to a file (JSONL with metadata by default)."
    )
    parser.add_argument(
        "-k", "--api-key", type=str, default=None, help="Malpedia API key (optional)"
    )
    parser.add_argument(
        "-f",
        "--family-id",
        type=str,
        default=None,
        help="Malpedia family ID (e.g., win.cobalt_strike)",
    )
    parser.add_argument(
        "-a", "--actor-id", type=str, default=None, help="Malpedia actor ID (e.g., apt.turla)"
    )
    parser.add_argument(
        "-s",
        "--search-term",
        type=str,
        default=None,
        help="Search term for fuzzy search (e.g., CobaltStrike)",
    )
    parser.add_argument(
        "-o", "--output", type=str, default="malpedia_urls.json", help="Output file path"
    )
    parser.add_argument(
        "-t",
        "--format",
        type=str,
        choices=["json", "csv"],
        default="json",
        help="Output format: 'json' (default, a single JSON list with all metadata), or 'csv' (CSV with columns for all metadata)",
    )

    args: argparse.Namespace = parser.parse_args()

    references: List[Dict[str, Any]] = collect_malpedia_references(
        api_key=args.api_key,
        family_id=args.family_id,
        actor_id=args.actor_id,
        search_term=args.search_term,
    )
    num_saved: int = save_url_list_to_file(references, args.output, fmt=args.format)
    if args.format == "json":
        print(f"Saved {num_saved} JSON objects to {args.output}")
    elif args.format == "csv":
        print(f"Saved {num_saved} rows to {args.output} (CSV)")
