import hashlib
import json
from typing import Any, Dict, List, Optional

# Readability constants for coercion helpers and debug preview
ALLOWED_SEVERITIES = frozenset({"info", "warn", "error"})
DEFAULT_SEVERITY = "info"

ALLOWED_SOURCES = frozenset({"features", "retrieval"})
DEFAULT_SOURCE = "features"

RAW_REPLY_PREVIEW_MAX_CHARS = 800


def parse_json_strict(reply: str) -> Dict[str, Any]:
    """Parse a JSON string and require the top-level value to be an object.

    Args:
        reply: A JSON-encoded string.

    Returns:
        A dictionary representing the parsed JSON object.

    Raises:
        ValueError: If the JSON is valid but the top-level is not an object.
        json.JSONDecodeError: If the string is not valid JSON.
    """
    parsed: Any = json.loads(reply)
    if not isinstance(parsed, dict):
        raise ValueError("Top-level JSON must be an object")
    return parsed


def clip_text(text: Optional[str], max_length: int) -> str:
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


def format_key_value(key: str, value: Any) -> str:
    """Format a key/value pair for human-readable bullet output.

    Lists and dicts are JSON-encoded to keep one-line formatting.
    """
    try:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        return f"{key}: {value}"
    except Exception:
        return f"{key}: {value}"


def repair_and_parse(reply: str) -> Dict[str, Any]:
    """Extract the first JSON object from a noisy string and parse it.

    This is a lenient helper useful when the model wraps JSON in prose or
    markdown. It looks for the first opening "{" and the last closing "}" and
    parses the substring between them.

    Args:
        reply: A string that contains a JSON object, possibly with extra text.

    Returns:
        A dictionary parsed from the extracted JSON object.

    Raises:
        ValueError: If no plausible JSON object bounds are found.
        json.JSONDecodeError: If the extracted substring is not valid JSON.
    """
    start_index: int = reply.find("{")
    end_index: int = reply.rfind("}")
    if start_index == -1 or end_index == -1 or end_index <= start_index:
        raise ValueError("No JSON object found in reply")
    json_slice = reply[start_index : end_index + 1]
    return json.loads(json_slice)


def truncate(text: str, max_chars: int) -> str:
    """Return a shortened version of text with ellipsis if it exceeds max_chars."""
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        # Edge case: if max is extremely small, return a string of dots of that size
        return "." * max_chars
    return text[: max_chars - 3] + "..."


def hash_messages(messages: List[Dict[str, str]]) -> str:
    """Compute a stable hash for a sequence of chat messages.

    Each message contributes the concatenation of its role and text/content,
    separated by newlines, to a SHA-256 digest. Messages can be dictionaries
    (with keys like "role", "text" or "content") or lightweight objects with
    attributes of the same names.

    Args:
        messages: A list of message-like items.

    Returns:
        A hex-encoded SHA-256 digest of the messages.
    """
    hasher = hashlib.sha256()

    for message in messages:
        # Support both dict-style and attribute-style message objects
        role = (
            getattr(message, "role", None) if not isinstance(message, dict) else message.get("role")
        ) or ""

        # Prefer "text", but fall back to "content" which is common in chat APIs
        if isinstance(message, dict):
            body = message.get("text") or message.get("content") or ""
        else:
            body = getattr(message, "text", None) or getattr(message, "content", None) or ""

        hasher.update(f"{role}\n{body}\n".encode("utf-8"))

    return hasher.hexdigest()


def coerce_severity(value: Any) -> str:
    """Normalize an arbitrary value to a known severity string.

    Allowed values: "info", "warn", "error" (case-insensitive). Defaults to "info".
    """
    severity = str(value or DEFAULT_SEVERITY).lower()
    return severity if severity in ALLOWED_SEVERITIES else DEFAULT_SEVERITY


def coerce_source(value: Any) -> str:
    """Normalize an arbitrary value to a known source string.

    Allowed values: "features", "retrieval" (case-insensitive). Defaults to "features".
    """
    source = str(value or DEFAULT_SOURCE).lower()
    return source if source in ALLOWED_SOURCES else DEFAULT_SOURCE


def fallback_result(
    error: str,
    prompt_hash: Optional[str] = None,
    raw_reply: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a conservative, well-formed result structure after a failure.

    This is used when an upstream LLM call or JSON parsing fails, ensuring
    downstream code receives a predictable shape with diagnostic metadata.
    """
    result: Dict[str, Any] = {
        "schema": "rexis.llmrag.classification.v1",
        "score": 0.0,
        "label": "unknown",
        "classification": [],
        "families": [],
        "capabilities": [],
        "tactics": [],
        "evidence": [],
        "uncertainty": "high",
        "notes": "LLM classification failed; returning fallback.",
    }

    meta: Dict[str, Any] = {
        "error": str(error),
        "prompt_hash": prompt_hash,
    }

    if raw_reply:
        # Prevent huge logs; show a short preview only
        meta["raw_reply_preview"] = truncate(str(raw_reply), max_chars=RAW_REPLY_PREVIEW_MAX_CHARS)

    result["meta"] = meta
    return result
