import json
from typing import Any, Dict, List, Optional

from haystack.dataclasses import ChatMessage
from rexis.tools.llm.utils import clip_text, format_key_value, truncate
from rexis.utils.types import (
    ImportsByCapability,
    PackerHints,
    Passage,
    ProgramInfo,
    SectionSummary,
    SummarizedFeatures,
)

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
    "Calibrate score heuristically: strong diverse capabilities with corroboration -> 0.75–0.95; "
    "single strong signal -> 0.45–0.65; weak/ambiguous -> 0.15–0.35; none -> ≤0.15. "
    "Prefer 1–3 concise classification tags that best describe the sample's high-level type."
)

MAX_FEATURE_LINES: int = 20
MAX_LINE_CHARS: int = 200
INCLUDE_METADATA_FOOTER: bool = True
DEFAULT_MAX_PASSAGES: int = 8
DEFAULT_PASSAGE_MAX_CHARS: int = 1000


def _render_feature_bullets(feature_summary: SummarizedFeatures) -> List[str]:
    """Build concise bullet lines from a feature summary mapping."""
    lines: List[str] = []
    program: ProgramInfo = feature_summary.get("program") or {}
    if program:
        for field, value in program.items():
            if value not in (None, "", []):
                lines.append(f"- {format_key_value(field, value)}")

    # Imports grouped by capability (already preprocessed upstream)
    imports_by_capability: ImportsByCapability = feature_summary.get("imports_by_capability") or {}
    if imports_by_capability:
        for capability, imports in imports_by_capability.items():
            if not imports:
                continue
            sample = ", ".join(clip_text(name, 40) for name in imports[:6])
            lines.append(
                f"- capability:{capability} -> imports: {sample}{'...' if len(imports) > 6 else ''}"
            )

    # Packer hints (if any)
    packer_hints: PackerHints = feature_summary.get("packer_hints") or []
    if packer_hints:
        for hint in packer_hints[:6]:
            lines.append(f"- packer_hint: {clip_text(str(hint), 80)}")

    sections: List[SectionSummary] = feature_summary.get("sections") or []
    for section in sections[:6]:  # keep brief
        name = section.get("name") or "?"
        entropy = section.get("entropy")
        size = section.get("size")
        permissions = section.get("perms") or section.get("attributes") or ""
        lines.append(
            f"- section {name}: size={size}, entropy={entropy}, perms={clip_text(str(permissions), 24)}"
        )
    if len(sections) > 6:
        lines.append(f"- (+{len(sections)-6} more sections)")

    # Clamp total lines
    return lines[:MAX_FEATURE_LINES]


def _render_retrieved_docs_block(retrieved_passages: List[Passage]) -> str:
    """Render a human-readable block summarizing retrieved passages."""
    lines: List[str] = []
    for index, passage in enumerate(retrieved_passages, start=1):
        doc_id = passage.get("doc_id") or f"doc_{index}"
        title = passage.get("title") or passage.get("source") or "Document"
        source = passage.get("source") or "unknown"
        text = passage.get("text") or ""
        lines.append(f"[{index}] {title} (id={doc_id}, source={source}): {text}")
    if not lines:
        lines.append("(no retrieved documents)")
    return "\n".join(lines)


def build_prompt_messages(
    feat_summary: SummarizedFeatures,
    retrieved_passages: List[Passage],
    json_mode: bool = True,
) -> List[ChatMessage]:
    """Build ChatMessage list for LLM classification prompt.

    The prompt includes a system role with strict schema instructions, a user
    message with structured context, retrieved documents, and task guidance.
    """
    system_text: str = (
        SYSTEM_PROMPT_BASE
        + (" Output must be JSON only." if json_mode else "")
        + "\n\n"
        + SCHEMA_HINT
    )

    # Context block (features summarized as short bullets)
    feature_lines: List[str] = _render_feature_bullets(feat_summary)
    context_block: str = "Context:\n" + "\n".join(
        clip_text(l, MAX_LINE_CHARS) for l in feature_lines
    )

    # Retrieved documents block (ID + source + clipped snippet)
    docs_block: str = "Retrieved Documents:\n" + _render_retrieved_docs_block(retrieved_passages)

    # Task instructions (explicit, stable)
    task_block: str = (
        "Tasks:\n"
        "- Classify the sample into a known malware family (or 'unknown' if undecidable).\n"
        "- Justify the classification using both static features and retrieved evidence; cite doc ids in 'evidence'.\n"
        "- Optionally compare with related families if relevant.\n"
        "- Return STRICT JSON only, following the required schema."
    )

    parts: List[str] = [context_block, docs_block, task_block]

    user_text: str = "\n\n".join(parts)

    return [
        ChatMessage.from_system(system_text),
        ChatMessage.from_user(user_text),
    ]


def compact_passages(
    retrieved_passages: List[Passage],
    max_items: int = DEFAULT_MAX_PASSAGES,
    max_chars: int = DEFAULT_PASSAGE_MAX_CHARS,
) -> List[Passage]:
    """Trim and normalize retrieved passages for prompt inclusion.

    Args:
        passages: Full retrieved passages with metadata and text.
        max_items: Maximum number of passages to keep.
        max_chars: Maximum characters for each passage's text body.

    Returns:
        A list of compact passage dicts with safe-length text.
    """
    compact: List[Passage] = []
    for src in retrieved_passages[:max_items]:
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
