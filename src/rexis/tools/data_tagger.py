import ast
import json
import re
import threading
import time
from typing import List, Optional

import openai
from rexis.utils.config import config
from rexis.utils.utils import LOGGER

_TAGGER_SEM: Optional[threading.BoundedSemaphore] = None


def _ensure_semaphore() -> threading.BoundedSemaphore:
    global _TAGGER_SEM
    if _TAGGER_SEM is None:
        max_conc = max(1, int(getattr(getattr(config, "tagger", {}), "max_concurrency", 2)))
        _TAGGER_SEM = threading.BoundedSemaphore(value=max_conc)
    return _TAGGER_SEM


def _parse_tags(content: str) -> List[str]:
    content = content.strip()
    # Try JSON first
    if content.startswith("["):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return [str(t).strip() for t in data if isinstance(t, (str, int, float))]
        except Exception:
            pass
    # literal_eval for Python-style lists
    try:
        tags_list = ast.literal_eval(content)
        if isinstance(tags_list, list):
            return [str(t).strip() for t in tags_list if isinstance(t, (str, int, float))]
    except Exception:
        pass
    # Regex to extract [ ... ]
    match = re.search(r"\[(.*?)\]", content, re.DOTALL)
    if match:
        items = match.group(1)
        tags = [i.strip().strip("\"'") for i in items.split(",") if i.strip()]
        if tags:
            return tags
    # Fallbacks: comma or newline separated
    if "," in content:
        tags = [t.strip().strip("\"'") for t in content.split(",") if t.strip()]
        if tags:
            return tags
    tags = [t.strip().strip("\"'") for t in content.splitlines() if t.strip()]
    return tags


def tag_chunk(text: str) -> List[str]:
    """
    Use an LLM to extract tags from a text chunk.
    Returns a list of tags.
    """
    tagger_cfg = getattr(config, "tagger", {})
    model = getattr(tagger_cfg, "model", None)
    api_key = getattr(tagger_cfg, "api_key", None)
    system_prompt = getattr(tagger_cfg, "system_prompt", None)
    temperature = getattr(tagger_cfg, "temperature", 0.2)
    max_tokens = getattr(tagger_cfg, "max_tokens", 256)
    # Allow disabling the tagger from config
    if getattr(getattr(config, "tagger", {}), "enabled", True) is False:
        return []

    sem = _ensure_semaphore()
    attempts = int(getattr(getattr(config, "tagger", {}), "max_retries", 3))
    backoff = float(getattr(getattr(config, "tagger", {}), "backoff_seconds", 1.0))
    for attempt in range(1, max(1, attempts) + 1):
        try:
            with sem:
                client = openai.Client(api_key=api_key)
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            content = response.choices[0].message.content.strip()
            tags = _parse_tags(content)
            if not tags:
                LOGGER.warning(
                    "Tagger: Unparseable response (len=%d). Truncated preview: %r",
                    len(content),
                    content[:160],
                )
            return tags
        except Exception as e:
            msg = str(e)
            if "rate_limit" in msg or "429" in msg:
                LOGGER.error(
                    "Tagger: Rate limited (attempt %d/%d). Retrying in %.2fs...",
                    attempt,
                    attempts,
                    backoff,
                )
                time.sleep(backoff)
                backoff *= 2
                continue
            LOGGER.error(f"Tagger: LLM tagging failed: {e}")
            break
    return []


def tag_chunks_batch(texts: List[str]) -> List[List[str]]:
    """Tag a batch of text chunks. Returns a list of tag lists (one per chunk)."""
    return [tag_chunk(text) for text in texts]
