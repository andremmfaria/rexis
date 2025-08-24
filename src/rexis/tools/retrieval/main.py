import re
import time
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple

from haystack import Document
from rexis.tools.retrieval.ranking import fuse_and_rerank
from rexis.tools.retrieval.searches import dense_search, keyword_search
from rexis.tools.retrieval.store import init_store
from rexis.utils.config import config
from rexis.utils.constants import CAPABILITY_BUCKETS, STRING_CATEGORY_PATTERNS
from rexis.utils.types import Features, Passage, ProgramInfo, RagNotes
from rexis.utils.utils import LOGGER

# Per-query item limits
IMPORTS_QUERY_ITEMS = 20
ENTROPY_SECTIONS_QUERY_ITEMS = 6
NETWORK_INDICATORS_QUERY_ITEMS = 7
CATEGORY_QUERY_ITEMS = 6
EXTRACT_CATEGORY_CAP = 7


def build_queries_from_features(features: Features, max_terms: int = 50) -> List[str]:
    """
    Build a small, deterministic set of hybrid-friendly queries out of the decompiler features.
    Returns short strings suitable for both dense and keyword retrieval.
    """
    print("[retrieval] Building queries from features...", flush=True)
    queries: List[str] = []
    imports_lc: List[str] = [
        i.lower() for i in (features.get("imports") or []) if isinstance(i, str)
    ]

    uniq_imports: List[str] = list(dict.fromkeys(imports_lc))

    def has(any_of: Set[str]) -> List[str]:
        return sorted(set([i for i in uniq_imports if any(tok in i for tok in any_of)]))

    def extract(patterns: List[Pattern[str]], strings: List[str], cap: int) -> List[str]:
        found: List[str] = []
        for s in strings:
            for rx in patterns:
                found.extend(rx.findall(s))
                if len(found) >= cap:
                    return found[:cap]
        return found[:cap]

    if uniq_imports:
        queries.append("imports: " + ", ".join(uniq_imports[: min(IMPORTS_QUERY_ITEMS, max_terms)]))

    # Section entropy signals: capture high-entropy sections (often packed/encrypted)
    sections: List[Dict[str, Any]] = features.get("sections") or []
    try:
        high_entropy: List[Tuple[str, float]] = [
            (s.get("name") or "", float(s.get("entropy")))
            for s in sections
            if isinstance(s, dict)
            and s.get("entropy") is not None
            and float(s.get("entropy")) >= 7.2
        ]
        # Sort by entropy desc and keep names only
        high_entropy = sorted(high_entropy, key=lambda x: x[1], reverse=True)
        if high_entropy:
            sec_names: List[str] = [
                n for n, _ in high_entropy[: min(ENTROPY_SECTIONS_QUERY_ITEMS, max_terms)]
            ]
            queries.append("high entropy sections: " + ", ".join(sec_names))
    except Exception:
        # Be resilient to malformed section metadata
        pass

    # Embedded strings: extract useful indicators (urls/domains/registry/file paths)
    raw_strings: List[str] = [s for s in (features.get("strings") or []) if isinstance(s, str)]
    if raw_strings:
        extracted_categories: Dict[str, List[str]] = {}
        for category, pattern_list in STRING_CATEGORY_PATTERNS.items():
            compiled_patterns: List[Pattern[str]] = [
                re.compile(p, re.IGNORECASE) for p in pattern_list
            ]
            extracted_categories[category] = extract(
                compiled_patterns, raw_strings, EXTRACT_CATEGORY_CAP
            )

        # Special handling for domains: avoid duplicating domains already present as part of URLs
        if "domains" in extracted_categories and "urls" in extracted_categories:
            domains: List[str] = [
                d
                for d in extracted_categories["domains"]
                if not any(d in u for u in extracted_categories["urls"])
            ]
            extracted_categories["domains"] = domains[:EXTRACT_CATEGORY_CAP]

        # Add queries for each category
        for category, values in extracted_categories.items():
            if not values:
                continue
            # Custom label for some categories
            if category in ("urls", "domains"):
                label = "network indicators"
                # Combine urls and domains once when processing 'urls'
                if category == "urls":
                    net_bits: List[str] = extracted_categories.get(
                        "urls", []
                    ) + extracted_categories.get("domains", [])
                    if net_bits:
                        queries.append(
                            f"{label}: "
                            + ", ".join(net_bits[: min(NETWORK_INDICATORS_QUERY_ITEMS, max_terms)])
                        )
                # Skip adding separate queries for urls/domains
                continue
            elif category == "registry_keys":
                label = "registry keys"
            elif category == "file_paths":
                label = "file paths"
            else:
                label = category.replace("_", " ")
            queries.append(f"{label}: " + ", ".join(values[: min(CATEGORY_QUERY_ITEMS, max_terms)]))

    # Semantic (capability-centric) prompts for all buckets
    for bucket, keywords in CAPABILITY_BUCKETS.items():
        hits = has(keywords)
        if hits:
            if bucket == "injection":
                queries.append("process injection via " + ", ".join(hits))
            elif bucket == "persistence":
                queries.append("persistence mechanisms " + ", ".join(hits))
            elif bucket == "network":
                queries.append("network communication using " + ", ".join(hits))
            elif bucket == "crypto":
                queries.append("crypto routines " + ", ".join(hits))
            elif bucket == "anti_debug":
                queries.append("anti-debugging using " + ", ".join(hits))
            else:
                queries.append(f"{bucket} features: " + ", ".join(hits))

    prog: ProgramInfo = features.get("program") or {}
    prog_info: str = ", ".join([f"{k}={v}" for k, v in prog.items()])
    queries.append(f"Program information: {prog_info}")

    built = queries[:max_terms]
    print(f"[retrieval] Built {len(built)} query prompts", flush=True)
    return built


def retrieve_context(
    queries: List[str],
    top_k_dense: int = 50,
    top_k_keyword: int = 50,
    final_top_k: int = 8,
    join_mode: str = "rrf",
    rerank_top_k: int = 0,
    ranker_model: str = "gpt-4o-mini",
    sources: Optional[List[str]] = None,
) -> Tuple[List[Passage], RagNotes]:
    """
    Hybrid retrieval (dense + keyword) -> RRF/merge -> optional re-rank.
    Returns:
      passages: [{doc_id, source, title, score, text}]
      rag_notes: dict with debug metrics and settings
    """
    t0: float = time.perf_counter()

    if not queries:
        print("[retrieval] No queries provided. Skipping retrieval.", flush=True)
        return [], RagNotes(note="no_queries")

    # Build filters only for known metadata keys
    filters: Optional[Dict[str, Any]] = {}
    if sources:
        filters["source"] = {"$in": list(sources)}
    if not filters:
        filters = None

    try:
        print("[retrieval] Initializing document store...", flush=True)
        store = init_store()
        print("[retrieval] Document store ready", flush=True)
    except Exception as e:
        LOGGER.error("Failed to init PgvectorDocumentStore: %s", e)
        print(f"[retrieval] ERROR: store init failed: {e}", flush=True)
        return [], RagNotes(error=f"store_init_failed: {e}")

    # Dense + keyword retrieval
    try:
        print(
            f"[retrieval] Running dense search (top_k={top_k_dense})...",
            flush=True,
        )
        dense_docs: List[Document] = dense_search(
            store, queries, top_k_dense=top_k_dense, metadata_filters=filters
        )
        print(f"[retrieval] Dense hits: {len(dense_docs)}", flush=True)
    except Exception as e:
        LOGGER.warning("Dense retrieval failed: %s", e)
        print(f"[retrieval] WARNING: Dense retrieval failed: {e}", flush=True)
        dense_docs = []

    try:
        print(
            f"[retrieval] Running keyword search (top_k={top_k_keyword})...",
            flush=True,
        )
        keyword_docs: List[Document] = keyword_search(
            store, queries, top_k_keyword=top_k_keyword, metadata_filters=filters
        )
        print(f"[retrieval] Keyword hits: {len(keyword_docs)}", flush=True)
    except Exception as e:
        LOGGER.warning("Keyword retrieval failed: %s", e)
        print(f"[retrieval] WARNING: Keyword retrieval failed: {e}", flush=True)
        keyword_docs = []

    fused_count: int = len({d.id for d in dense_docs} | {d.id for d in keyword_docs})

    # Pick a ranking query: prefer a semantic one (not the 'imports:' line)
    query_for_ranker: str = next(
        (q for q in queries if not q.lower().startswith("imports:")), queries[0]
    )

    try:
        print(
            f"[retrieval] Fusing results (mode={join_mode}, rerank_top_k={rerank_top_k}, final_top_k={final_top_k})...",
            flush=True,
        )
        final_docs: List[Document] = fuse_and_rerank(
            dense_docs=dense_docs,
            keyword_docs=keyword_docs,
            join_mode=join_mode,
            rerank_top_k=rerank_top_k,
            final_top_k=final_top_k,
            ranker_model=ranker_model,
            query_for_ranker=query_for_ranker,
        )
    except Exception as e:
        LOGGER.warning("Fusion/rerank failed: %s", e)
        print(
            f"[retrieval] WARNING: Fusion/rerank failed: {e}. Falling back to simple merge.",
            flush=True,
        )
        all_docs: List[Document] = dense_docs + keyword_docs
        seen: Set[str] = set()
        deduped: List[Document] = []
        for d in all_docs:
            if d.id in seen:
                continue
            seen.add(d.id)
            deduped.append(d)
        final_docs = deduped[:final_top_k]

    # Format passages for the LLM
    passages: List[Passage] = []
    for d in final_docs:
        meta: Dict[str, Any] = d.meta or {}
        passages.append(
            {
                "doc_id": d.id,
                "source": meta.get("source"),  # may be None if not indexed
                "title": meta.get("title") or meta.get("file_name") or meta.get("url"),
                "score": float(d.score) if d.score is not None else None,
                "text": (d.content or "")[:4000],
            }
        )

    rag_notes: RagNotes = {
        "query_count": len(queries),
        "top_k_dense": top_k_dense,
        "top_k_keyword": top_k_keyword,
        "join_mode": join_mode,
        "rerank_top_k": rerank_top_k,
        "final_top_k": final_top_k,
        "filters": {"sources": sources or []},
        "ranker_model": ranker_model,
        "embedding_model": config.models.openai.embedding_model,
        "metric": "cosine_similarity",
        "dense_hits": len(dense_docs),
        "keyword_hits": len(keyword_docs),
        "fused_unique": fused_count,
        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
    }
    print(
        (
            f"[retrieval] Retrieved {len(passages)} passages"
            f" (dense={len(dense_docs)}, keyword={len(keyword_docs)}, fused_unique={fused_count})"
            f" in {rag_notes['elapsed_ms']} ms"
        ),
        flush=True,
    )
    return passages, rag_notes
