import json
from typing import Any, Dict, List, Tuple

from haystack import Document
from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.components.joiners import DocumentJoiner
from haystack.utils import Secret
from rexis.utils.config import config
from rexis.utils.constants import AUTH_BONUS
from rexis.utils.utils import LOGGER


def _truncate(text: str, max_chars: int = 1000) -> str:
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def build_llm_rerank_messages(query: str, candidates: List[Document]) -> List[Dict[str, str]]:
    """
    Build a compact, JSON-only rerank prompt for OpenAI.
    """
    print(
        f"[ranking] Building LLM rerank messages for {len(candidates)} candidates…",
        flush=True,
    )
    sys: str = (
        "You are ranking passages for malware analysis. "
        "Given a query and up to 20 candidate passages, return STRICT JSON: "
        '[{"doc_id": str, "score": float in [0,1]} ...], highest scores for most relevant items. '
        "Do not include any text outside the JSON. Consider exact API names, capabilities, family hints, and technical fit."
    )
    lines: List[Dict[str, Any]] = []
    for d in candidates:
        meta: Dict[str, Any] = d.meta or {}
        lines.append(
            {
                "doc_id": d.id,
                "source": meta.get("source"),
                "title": meta.get("title") or meta.get("file_name") or meta.get("url"),
                "excerpt": _truncate(d.content or "", 750),
            }
        )
    user: Dict[str, Any] = {
        "query": query,
        "candidates": lines,
    }
    return [
        {"role": "system", "content": sys},
        {"role": "user", "content": json.dumps(user)},
    ]


def apply_authority_bias_and_diversify(
    ordered_docs: List[Document],
    scores: Dict[str, float],
    final_top_k: int,
    max_per_source: int = 3,
) -> List[Document]:
    """
    Apply small source-based boosts and ensure we don't over-sample one source.
    """
    print(
        f"[ranking] Applying authority bias and diversification (max_per_source={max_per_source}, final_top_k={final_top_k})…",
        flush=True,
    )

    # Combine scores + authority bonus
    scored: List[Tuple[float, Document]] = []
    for d in ordered_docs:
        src: str = (d.meta or {}).get("source", "") or ""
        base: float = float(scores.get(d.id, 0.0))
        bonus: float = AUTH_BONUS.get(str(src).lower(), 0.0)
        scored.append((base + bonus, d))

    # Sort by combined score desc
    scored.sort(key=lambda x: x[0], reverse=True)

    # Diversify: cap per source, then fill up to final_top_k
    from collections import defaultdict

    per_src: Dict[str, int] = defaultdict(int)
    selected: List[Document] = []
    backfill: List[Document] = []
    for s, d in scored:
        src = ((d.meta or {}).get("source", "") or "").lower()
        if per_src[src] < max_per_source and len(selected) < final_top_k:
            selected.append(d)
            per_src[src] += 1
        else:
            backfill.append(d)
        if len(selected) >= final_top_k:
            break

    # Backfill if we didn't reach K
    for d in backfill:
        if len(selected) >= final_top_k:
            break
        selected.append(d)
    out = selected[:final_top_k]
    print(f"[ranking] Selected {len(out)} documents after diversification", flush=True)
    return out


def fuse_and_rerank(
    dense_docs: List[Document],
    keyword_docs: List[Document],
    join_mode: str,
    rerank_top_k: int,
    final_top_k: int,
    ranker_model: str,
    query_for_ranker: str,
) -> List[Document]:
    """
    Fuse dense + keyword with RRF/merge, optionally rerank with OpenAI (listwise) when rerank_top_k > 0.
    Returns the top `final_top_k` Documents.
    """
    # 1) Fuse (RRF or merge) and collect candidates
    joiner_mode: str = "reciprocal_rank_fusion" if join_mode.lower() == "rrf" else "merge"
    cand_k: int = max(final_top_k, rerank_top_k or 0) or final_top_k
    print(
        f"[ranking] Fusing dense+keyword with {joiner_mode} (K={cand_k})…",
        flush=True,
    )
    joiner = DocumentJoiner(join_mode=joiner_mode, top_k=cand_k)
    fused: List[Document] = joiner.run(documents=[dense_docs, keyword_docs])["documents"]
    print(
        f"[ranking] Fused candidates: {len(fused)} (dense={len(dense_docs)}, keyword={len(keyword_docs)})",
        flush=True,
    )

    if not fused:
        print("[ranking] No fused results; returning empty list", flush=True)
        return []

    # 2) If rerank is disabled, return the fused top-k directly
    if rerank_top_k <= 0:
        print("[ranking] Rerank disabled; returning fused top-k", flush=True)
        return fused[:final_top_k]

    # Limit candidates to rerank_top_k
    candidates: List[Document] = fused[:rerank_top_k]

    # 3) LLM listwise rerank with OpenAI (JSON-only)
    try:
        print(
            f"[ranking] Reranking top {rerank_top_k} candidates with model '{ranker_model}'…",
            flush=True,
        )
        messages: List[Dict[str, str]] = build_llm_rerank_messages(query_for_ranker, candidates)
        gen: OpenAIChatGenerator = OpenAIChatGenerator(
            api_key=Secret.from_token(config.models.openai.api_key),
            model=ranker_model,
            temperature=0.0,
            max_tokens=400,
        )
        gen.warm_up()
        res: Dict[str, Any] = gen.run(messages=messages)
        reply: str = (res.get("replies") or [""])[0]
        data: List[Dict[str, Any]] = json.loads(reply)

        # Expect a list of {"doc_id": "...", "score": number}
        score_by_id: Dict[str, float] = {}
        for item in data:
            did = str(item.get("doc_id", "")).strip()
            sc = float(item.get("score", 0.0))
            if did:
                score_by_id[did] = sc
        print(
            f"[ranking] LLM provided scores for {len(score_by_id)} documents",
            flush=True,
        )

        # Order the candidate docs per LLM scores, then apply authority bias + diversification
        # Keep original fused order as a tiebreaker by adding a tiny epsilon
        fused_order: Dict[str, int] = {d.id: i for i, d in enumerate(candidates)}
        ordered: List[Document] = sorted(
            candidates,
            key=lambda d: (score_by_id.get(d.id, 0.0), -fused_order.get(d.id, 0)),
            reverse=True,
        )
        final_docs: List[Document] = apply_authority_bias_and_diversify(ordered, score_by_id, final_top_k)

        # If something went wrong or we got too few, back off to fused
        if len(final_docs) < final_top_k:
            final_docs = (final_docs + [d for d in fused if d not in final_docs])[:final_top_k]

        print(f"[ranking] Final selection after rerank: {len(final_docs)} docs", flush=True)
        return final_docs

    except Exception as e:
        # Fail-safe: fall back to fused top-k
        LOGGER.warning("OpenAI rerank failed (%s). Falling back to fused results.", e)
        print(
            f"[ranking] WARNING: OpenAI rerank failed: {e}. Falling back to fused results",
            flush=True,
        )
        return fused[:final_top_k]
