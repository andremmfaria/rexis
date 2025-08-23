import json
from typing import Any, Dict, List, Optional

from haystack.dataclasses import ChatMessage
from rexis.tools.llm.utils import truncate

SYSTEM_PROMPT_BASE: str = (
    "You are a precise malware analyst. You must produce a JSON verdict following the given schema. "
    "If uncertain, set label='unknown' and uncertainty='high'. Prefer concise, actionable evidence."
)

SCHEMA_HINT: str = (
    "Return STRICT JSON only, no prose outside JSON. The JSON object MUST include keys:\n"
    '  schema="rexis.llmrag.classification.v1", score (0..1), label ("malicious"|"suspicious"|"benign"|"unknown"),\n'
    "  classification (list of strings; e.g., ransomware, trojan, worm, downloader, dropper, rootkit, "
    "banker, stealer, backdoor, botnet, keylogger, adware, spyware, wiper, rat, cryptominer),\n"
    "  families (list of strings), capabilities (list of strings), tactics (list of strings),\n"
    "  evidence (list of objects with: id, title, detail, severity in {info,warn,error}, "
    "source in {features,retrieval}, doc_ref),\n"
    '  uncertainty in {"low","medium","high"} and optional notes.\n'
    "Constrain evidence to 4–8 diverse items. Use source=features for imports/sections-based inferences; "
    "use source=retrieval and doc_ref=<doc_id> to cite passages. "
    "Map capability names to analyst terminology (injection, persistence, networking, crypto, anti-debug, "
    "exfiltration, obfuscation, c2). "
    "Calibrate score heuristically: strong diverse capabilities with corroboration → 0.75–0.95; "
    "single strong signal → 0.45–0.65; weak/ambiguous → 0.15–0.35; none → ≤0.15. "
    "Prefer 1–3 concise classification tags that best describe the sample's high-level type."
)

K_RETRIEVED_DOCS: int = 3
MAX_FEATURE_LINES: int = 14
MAX_LINE_CHARS: int = 160
MAX_DOC_SNIPPET_CHARS: int = 360
INCLUDE_METADATA_FOOTER: bool = True
DEFAULT_MAX_PASSAGES: int = 8
DEFAULT_PASSAGE_MAX_CHARS: int = 900


def _clip_text(text: Optional[str], max_length: int) -> str:
    """Safely clip a string to at most ``max_length`` characters, adding an ellipsis if clipped.

    Args:
        text: The string to clip. If None or empty, returns an empty string.
        max_length: Maximum allowed length of the returned string.

    Returns:
        The clipped string (with trailing ellipsis if truncation occurred).
    """
    if not text:
        return ""
    return text if len(text) <= max_length else (text[: max(0, max_length - 1)] + "...")


def _format_key_value(key: str, value: Any) -> str:
    """Format a key/value pair for human-readable bullet output.

    Lists and dicts are JSON-encoded to keep one-line formatting.
    """
    try:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        return f"{key}: {value}"
    except Exception:
        return f"{key}: {value}"


def _render_feature_bullets(feature_summary: Dict[str, Any]) -> List[str]:
    """Build concise bullet lines from a feature summary mapping."""
    lines: List[str] = []
    program: Dict[str, Any] = (feature_summary or {}).get("program") or {}
    if program:
        for field in ("name", "format", "language", "compiler", "image_base", "size", "sha256"):
            if program.get(field) not in (None, "", []):
                lines.append(f"- {_format_key_value(field, program.get(field))}")

    # Imports grouped by capability (already preprocessed upstream)
    imports_by_capability: Dict[str, List[str]] = (feature_summary or {}).get("imports_by_capability") or {}
    if imports_by_capability:
        for capability, imports in imports_by_capability.items():
            if not imports:
                continue
            sample = ", ".join(_clip_text(name, 40) for name in imports[:6])
            lines.append(f"- capability:{capability} → imports: {sample}{'...' if len(imports) > 6 else ''}")

    # Packer hints (if any)
    packer_hints: Dict[str, Any] = (feature_summary or {}).get("packer_hints") or {}
    if packer_hints:
        for hint_key, hint_value in packer_hints.items():
            lines.append(f"- packer_hint:{hint_key} → {_clip_text(str(hint_value), 80)}")

    # Sections (name / perms / entropy / size)
    sections: List[Dict[str, Any]] = (feature_summary or {}).get("sections") or []
    for section in sections[:6]:  # keep brief
        name = section.get("name") or "?"
        entropy = section.get("entropy")
        size = section.get("size")
        permissions = section.get("perms") or section.get("attributes") or ""
        lines.append(
            f"- section {name}: size={size}, entropy={entropy}, perms={_clip_text(str(permissions), 24)}"
        )
    if len(sections) > 6:
        lines.append(f"- (+{len(sections)-6} more sections)")

    # Clamp total lines
    return lines[:MAX_FEATURE_LINES]


def _render_retrieved_docs_block(retrieved_passages: List[Dict[str, Any]], top_k: int) -> str:
    """Render a human-readable block summarizing the top-k retrieved passages."""
    lines: List[str] = []
    for index, passage in enumerate(retrieved_passages[:top_k], start=1):
        doc_id = passage.get("id") or passage.get("doc_id") or f"doc_{index}"
        title = passage.get("title") or passage.get("source") or "Document"
        source = passage.get("source") or passage.get("origin") or "unknown"
        # Try typical content keys
        snippet = passage.get("content") or passage.get("text") or passage.get("snippet") or ""
        snippet = _clip_text(str(snippet).strip().replace("\n", " "), MAX_DOC_SNIPPET_CHARS)
        lines.append(f"[{index}] {title} (id={doc_id}, source={source}): {snippet}")
    if not lines:
        lines.append("(no retrieved documents)")
    return "\n".join(lines)


def _render_metadata_footer(feature_summary: Dict[str, Any], retrieved_passages: List[Dict[str, Any]]) -> str:
    """Build a compact metadata footer with sample identifiers and retrieved ids."""
    program: Dict[str, Any] = (feature_summary or {}).get("program") or {}
    sha256 = program.get("sha256") or "unknown"
    sample_name = program.get("name") or "unknown"
    doc_ids = [
        p.get("id") or p.get("doc_id")
        for p in retrieved_passages[:K_RETRIEVED_DOCS]
        if (p.get("id") or p.get("doc_id"))
    ]
    return f"Metadata: sample_name={sample_name}, sha256={sha256}, retrieved_ids={doc_ids}"


def build_prompt_messages(
    feat_summary: Dict[str, Any],
    passages: List[Dict[str, Any]],
    json_mode: bool = True,
    k_docs: int = K_RETRIEVED_DOCS,
) -> List[ChatMessage]:
    """Build ChatMessage list for LLM classification prompt.

    The prompt includes a system role with strict schema instructions, a user
    message with structured context, retrieved documents, and task guidance.
    """
    system_text = SYSTEM_PROMPT_BASE + (" Output must be JSON only." if json_mode else "")
    system_text = system_text + "\n\n" + SCHEMA_HINT

    # Context block (features summarized as short bullets)
    feature_lines = _render_feature_bullets(feat_summary)
    context_block = "Context:\n" + "\n".join(_clip_text(l, MAX_LINE_CHARS) for l in feature_lines)

    # Retrieved documents block (ID + source + clipped snippet)
    docs_block = "Retrieved Documents:\n" + _render_retrieved_docs_block(passages, k_docs)

    # Task instructions (explicit, stable)
    task_block = (
        "Task:\n"
        "- Classify the sample into a known malware family (or 'unknown' if undecidable).\n"
        "- Justify the classification using both static features and retrieved evidence; cite doc ids in 'evidence'.\n"
        "- Optionally compare with related families if relevant.\n"
        "- Return STRICT JSON only, following the required schema."
    )

    parts: List[str] = [context_block, docs_block, task_block]
    if INCLUDE_METADATA_FOOTER:
        parts.append(_render_metadata_footer(feat_summary, passages))

    user_text = "\n\n".join(parts)

    return [
        ChatMessage.from_system(system_text),
        ChatMessage.from_user(user_text),
    ]


def compact_passages(
    passages: List[Dict[str, Any]],
    max_items: int = DEFAULT_MAX_PASSAGES,
    max_chars: int = DEFAULT_PASSAGE_MAX_CHARS,
) -> List[Dict[str, Any]]:
    """Trim and normalize retrieved passages for prompt inclusion.

    Args:
        passages: Full retrieved passages with metadata and text.
        max_items: Maximum number of passages to keep.
        max_chars: Maximum characters for each passage's text body.

    Returns:
        A list of compact passage dicts with safe-length text.
    """
    compact: List[Dict[str, Any]] = []
    for src in passages[:max_items]:
        compact.append(
            {
                "doc_id": src.get("doc_id"),
                "source": src.get("source"),
                "title": src.get("title"),
                "score": src.get("score"),
                "text": truncate(str(src.get("text") or ""), max_chars=max_chars),
            }
        )

    return compact
