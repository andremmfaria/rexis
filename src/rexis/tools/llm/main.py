import json
from typing import Any, Dict, List, Optional

from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from haystack.utils import Secret
from rexis.tools.llm.features import summarize_features
from rexis.tools.llm.messages import build_messages, compact_passages
from rexis.tools.llm.utils import (
    coerce_severity,
    coerce_source,
    fallback_result,
    hash_messages,
    parse_json_strict,
    repair_and_parse,
)
from rexis.utils.config import config
from rexis.utils.constants import (
    SCORE_THRESHOLD_BENIGN_MAX,
    SCORE_THRESHOLD_MALICIOUS,
    SCORE_THRESHOLD_SUSPICIOUS,
)
from rexis.utils.types import Passage
from rexis.utils.utils import LOGGER


def llm_classify(
    features: Dict[str, Any],
    passages: List[Passage],
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 800,
    seed: Optional[int] = None,
    json_mode: bool = True,
) -> Dict[str, Any]:
    """
    Runs an OpenAI chat model to classify a sample based on decompiler features + retrieved passages.

    Returns a dict shaped like:
      {
        "schema": "rexis.llmrag.classification.v1",
        "score": 0.0,
        "label": "malicious|suspicious|benign|unknown",
        "families": [],
        "capabilities": [],
        "tactics": [],
        "evidence": [{"id","title","detail","severity","source","doc_ref"}],
        "uncertainty": "low|medium|high",
        "notes": "optional"
      }
    """
    # 1) Build messages
    print(
        f"[llm] Starting classification | model={model} temp={temperature} max_tokens={max_tokens} json_mode={json_mode}",
        flush=True,
    )
    print(f"[llm] Passages provided: {len(passages)} (will compact)", flush=True)
    feat_summary: Dict[str, Any] = summarize_features(features)
    compact: List[Dict[str, Any]] = compact_passages(passages, max_items=8, max_chars=900)
    print(f"[llm] Passages after compaction: {len(compact)} (limit 8)", flush=True)

    messages: List[ChatMessage] = build_messages(feat_summary, compact, json_mode=json_mode)
    prompt_hash: str = hash_messages(messages)
    print(f"[llm] Built {len(messages)} messages | prompt_hash={prompt_hash[:20]}...", flush=True)

    # 2) Call OpenAI
    try:
        print(f"[llm] Calling LLM provider (OpenAI) with model '{model}'...", flush=True)
        gen: OpenAIChatGenerator = OpenAIChatGenerator(
            api_key=Secret.from_token(config.models.openai.api_key),
            model=model,
            generation_kwargs={"temperature": temperature, "max_tokens": max_tokens},
        )

        res: Dict[str, List[ChatMessage]] = gen.run(messages=messages)

        LOGGER.debug(f"[llm] LLM response: {res}")

        raw_reply: str = (res.get("replies") or [""])[0].text

        print(f"[llm] LLM reply received ({len(raw_reply)} chars)", flush=True)
    except Exception as e:
        LOGGER.error("LLM classify call failed: %s", e)
        return fallback_result(error=f"llm_call_failed: {e}", prompt_hash=prompt_hash)

    # 3) Parse / repair JSON
    try:
        print("[llm] Parsing JSON (strict)...", flush=True)
        parsed: Dict[str, Any] = parse_json_strict(raw_reply)
        print("[llm] Strict JSON parse: OK", flush=True)
    except Exception as e:
        LOGGER.warning("Strict JSON parse failed; attempting repair: %s", e)
        try:
            parsed = repair_and_parse(raw_reply)
            print("[llm] JSON repair parse: OK", flush=True)
        except Exception as e2:
            LOGGER.error("JSON repair failed: %s", e2)
            return fallback_result(
                error="json_parse_failed", prompt_hash=prompt_hash, raw_reply=raw_reply
            )

    # 4) Validate + coerce into our schema
    validated: Dict[str, Any] = _validate_and_normalize(parsed)
    try:
        lbl = str(validated.get("label"))
        sc = float(validated.get("score", 0.0))
        print(f"[llm] Validation complete | label={lbl} score={sc}", flush=True)
    except Exception:
        print("[llm] Validation complete", flush=True)

    validated["meta"] = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
        "json_mode": json_mode,
        "prompt_hash": prompt_hash,
        "passages_used": [p.get("doc_id") for p in compact],
    }

    print("[llm] Classification complete", flush=True)
    return validated


def _validate_and_normalize(obj: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "schema": "rexis.llmrag.classification.v1",
        "score": 0.0,
        "label": "unknown",
        "families": [],
        "capabilities": [],
        "tactics": [],
        "evidence": [],
        "uncertainty": "high",
    }

    try:
        score: float = float(obj.get("score", 0.0))
    except Exception:
        score = 0.0
    score = max(0.0, min(1.0, score))
    out["score"] = round(score, 4)

    label: str = str(obj.get("label", "unknown")).lower()
    if label not in {"malicious", "suspicious", "benign", "unknown"}:
        if score >= SCORE_THRESHOLD_MALICIOUS:
            label = "malicious"
        elif score >= SCORE_THRESHOLD_SUSPICIOUS:
            label = "suspicious"
        elif score <= SCORE_THRESHOLD_BENIGN_MAX:
            label = "benign"
        else:
            label = "unknown"
    out["label"] = label

    def _norm_list(x: Any, typ=str, limit: int = 16) -> List[Any]:
        vals: List[Any] = []
        for v in x or []:
            try:
                vals.append(typ(v))
            except Exception:
                continue
            if len(vals) >= limit:
                break
        return vals

    out["families"] = _norm_list(obj.get("families"), str, 8)
    out["capabilities"] = _norm_list(obj.get("capabilities"), str, 12)
    out["tactics"] = _norm_list(obj.get("tactics"), str, 12)

    ev_in: List[Dict[str, Any]] = obj.get("evidence") or []
    ev_out: List[Dict[str, Any]] = []
    for e in ev_in[:8]:
        try:
            ev_out.append(
                {
                    "id": str(e.get("id") or "evidence"),
                    "title": str(e.get("title") or "Evidence"),
                    "detail": str(e.get("detail") or ""),
                    "severity": coerce_severity(e.get("severity")),
                    "source": coerce_source(e.get("source")),
                    "doc_ref": str(e.get("doc_ref") or ""),
                }
            )
        except Exception:
            continue
    out["evidence"] = ev_out

    unc: str = str(obj.get("uncertainty", "high")).lower()
    if unc not in {"low", "medium", "high"}:
        unc = "high"
    out["uncertainty"] = unc

    if isinstance(obj.get("notes"), str) and obj["notes"].strip():
        out["notes"] = obj["notes"].strip()

    return out
