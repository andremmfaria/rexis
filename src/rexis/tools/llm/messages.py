"""Helpers to build LLM prompts and compact retrieved passages.

This module focuses on clarity and predictable shapes for messages fed to
LLM chat APIs. Public behavior is unchanged; only readability is improved.
"""

import json
from typing import Any, Dict, List

from haystack.dataclasses import ChatMessage
from rexis.tools.llm.utils import truncate
from rexis.utils.constants import SCHEMA_HINT, SYSTEM_PROMPT_BASE


def build_prompt_messages(
    feat_summary: Dict[str, Any],
    passages: List[Dict[str, Any]],
    json_mode: bool = True,
) -> List[ChatMessage]:
    """Construct system and user messages to prompt the LLM.

    Args:
        feat_summary: High-level features from static analysis (program, imports, sections, etc.).
        passages: Retrieved context passages to ground the response.
        json_mode: When True, emphasizes that the output must be JSON only.

    Returns:
        A list containing a system and a user ChatMessage.
    """
    system_prompt: str = SYSTEM_PROMPT_BASE + (" Output must be JSON only." if json_mode else "")

    user_payload: Dict[str, Any] = {
        "program": feat_summary.get("program"),
        "imports_by_capability": feat_summary.get("imports_by_capability"),
        "packer_hints": feat_summary.get("packer_hints"),
        "sections": feat_summary.get("sections"),
        "retrieved_passages": passages,
    }

    return [
        ChatMessage.from_system(system_prompt + "\n\n" + SCHEMA_HINT),
        ChatMessage.from_user(json.dumps(user_payload, ensure_ascii=False)),
    ]


DEFAULT_MAX_PASSAGES = 8
DEFAULT_PASSAGE_MAX_CHARS = 900


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
