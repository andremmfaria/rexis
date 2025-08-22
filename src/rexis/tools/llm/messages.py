import json
from typing import Any, Dict, List

from haystack.dataclasses import ChatMessage
from rexis.tools.llm.utils import truncate


def build_prompt_messages(
    feat_summary: Dict[str, Any],
    passages: List[Dict[str, Any]],
    json_mode: bool = True,
) -> List[ChatMessage]:
    schema_hint: str = (
        "Return STRICT JSON only, no prose outside JSON. The JSON object MUST include keys:\n"
        '  schema="rexis.llmrag.classification.v1", score (0..1), label ("malicious"|"suspicious"|"benign"|"unknown"),\n'
        "  families (list of strings), capabilities (list of strings), tactics (list of strings),\n"
        "  evidence (list of objects with: id, title, detail, severity in {info,warn,error}, source in {features,retrieval}, doc_ref),\n"
        '  uncertainty in {"low","medium","high"} and optional notes.\n'
        "Constrain evidence to 4-8 diverse items. Use source=features for imports/sections-based inferences; "
        "use source=retrieval and doc_ref=<doc_id> to cite passages. "
        "Map capability names to malware analyst terminology (injection, persistence, networking, crypto, anti-debug, exfiltration, obfuscation, c2). "
        "Calibrate score heuristically: strong diverse capabilities with corroboration → 0.75–0.95; single strong signal → 0.45–0.65; weak/ambiguous → 0.15–0.35; none → ≤0.15."
    )

    sys: str = (
        "You are a precise malware analyst. You must produce a JSON verdict following the given schema. "
        "If uncertain, set label='unknown' and uncertainty='high'. Prefer concise, actionable evidence."
    )
    if json_mode:
        sys += " Output must be JSON only."

    user_payload: Dict[str, Any] = {
        "program": feat_summary.get("program"),
        "imports_by_capability": feat_summary.get("imports_by_capability"),
        "packer_hints": feat_summary.get("packer_hints"),
        "sections": feat_summary.get("sections"),
        "retrieved_passages": passages,
    }

    return [
        ChatMessage.from_system(sys + "\n\n" + schema_hint),
        ChatMessage.from_user(json.dumps(user_payload, ensure_ascii=False)),
    ]


def compact_passages(
    passages: List[Dict[str, Any]], max_items: int = 8, max_chars: int = 900
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in passages[:max_items]:
        out.append(
            {
                "doc_id": p.get("doc_id"),
                "source": p.get("source"),
                "title": p.get("title"),
                "score": p.get("score"),
                "text": truncate(str(p.get("text") or ""), max_chars=max_chars),
            }
        )
    return out
