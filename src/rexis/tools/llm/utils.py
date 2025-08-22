import hashlib
import json
from typing import Any, Dict, List, Optional


def parse_json_strict(reply: str) -> Dict[str, Any]:
    data: Any = json.loads(reply)
    if not isinstance(data, dict):
        raise ValueError("Top-level JSON must be an object")
    return data


def repair_and_parse(reply: str) -> Dict[str, Any]:
    start: int = reply.find("{")
    end: int = reply.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found in reply")
    return json.loads(reply[start : end + 1])


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def hash_messages(messages: List[Dict[str, str]]) -> str:
    m = hashlib.sha256()
    for msg in messages:
        m.update((msg.role + "\n" + (msg.text or "") + "\n").encode("utf-8"))
    return m.hexdigest()


def coerce_severity(v: Any) -> str:
    sev = str(v or "info").lower()
    return sev if sev in {"info", "warn", "error"} else "info"


def coerce_source(v: Any) -> str:
    src = str(v or "features").lower()
    return src if src in {"features", "retrieval"} else "features"


def fallback_result(
    error: str,
    prompt_hash: Optional[str] = None,
    raw_reply: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Safe default when the LLM call or JSON parsing fails.
    """
    result: Dict[str, Any] = {
        "schema": "rexis.llmrag.classification.v1",
        "score": 0.0,
        "label": "unknown",
        "families": [],
        "capabilities": [],
        "tactics": [],
        "evidence": [],
        "uncertainty": "high",
        "notes": "LLM classification failed; returning fallback.",
    }
    debug: Dict[str, Any] = {
        "error": str(error),
        "prompt_hash": prompt_hash,
    }
    if raw_reply:
        # prevent huge logs; show a short preview only
        debug["raw_reply_preview"] = truncate(str(raw_reply), max_chars=800)
    result["_debug"] = debug
    return result
