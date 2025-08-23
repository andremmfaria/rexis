import json
from typing import Any, Dict, List, Optional

from haystack.components.generators.chat import OpenAIChatGenerator
from haystack.dataclasses import ChatMessage
from haystack.utils import Secret
from rexis.tools.llm.features import summarize_features
from rexis.tools.llm.messages import build_prompt_messages, compact_passages
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
from rexis.utils.types import Features, Passage, SummarizedFeatures
from rexis.utils.utils import LOGGER


def llm_classify(
    features: Features,
    passages: List[Passage],
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 800,
    seed: Optional[int] = None,
    json_mode: bool = True,
) -> Dict[str, Any]:
    """Classify a sample with an OpenAI chat model using extracted features and retrieved passages.

    Contract
    - Inputs: features (arbitrary dict), passages (retrieved context), model name, generation parameters.
    - Output: normalized classification object following schema "rexis.llmrag.classification.v1".
    - Errors: on provider/JSON failures, returns a best-effort fallback with error info embedded.
    """
    # 1) Build messages
    print(
        f"[llm] Starting classification | model={model} temp={temperature} max_tokens={max_tokens} json_mode={json_mode}",
        flush=True,
    )
    print(f"[llm] Passages provided: {len(passages)} (will compact)", flush=True)
    # Summarize the extracted features and compact passages to fit model context.
    features_summary: SummarizedFeatures = summarize_features(features)
    compacted_passages: List[Passage] = compact_passages(passages, max_items=8, max_chars=900)
    print(f"[llm] Passages after compaction: {len(compacted_passages)} (limit 8)", flush=True)

    # Build chat messages and compute a prompt hash to trace this request.
    prompt_messages: List[ChatMessage] = build_prompt_messages(
        features_summary, compacted_passages, json_mode=json_mode
    )
    prompt_hash: str = hash_messages(prompt_messages)
    print(
        f"[llm] Built {len(prompt_messages)} messages | prompt_hash={prompt_hash[:20]}...",
        flush=True,
    )

    # 2) Call OpenAI
    try:
        print(f"[llm] Calling LLM provider (OpenAI) with model '{model}'...", flush=True)
        gen: OpenAIChatGenerator = OpenAIChatGenerator(
            api_key=Secret.from_token(config.models.openai.api_key),
            model=model,
            generation_kwargs={"temperature": temperature, "max_tokens": max_tokens},
        )

        result: Dict[str, List[ChatMessage]] = gen.run(messages=prompt_messages)

        LOGGER.debug(f"[llm] LLM response: {result}")

        raw_model_reply: str = (result.get("replies"))[0].text

        print(f"[llm] LLM reply received ({len(raw_model_reply)} chars)", flush=True)
    except Exception as e:
        LOGGER.error("LLM classify call failed: %s", e)
        return fallback_result(error=f"llm_call_failed: {e}", prompt_hash=prompt_hash)

    # 3) Parse / repair JSON
    try:
        print("[llm] Parsing JSON (strict)...", flush=True)
        parsed_json: Dict[str, Any] = parse_json_strict(raw_model_reply)
        print("[llm] Strict JSON parse: OK", flush=True)
    except Exception as e:
        LOGGER.warning("Strict JSON parse failed; attempting repair: %s", e)
        try:
            parsed_json = repair_and_parse(raw_model_reply)
            print("[llm] JSON repair parse: OK", flush=True)
        except Exception as e2:
            LOGGER.error("JSON repair failed: %s", e2)
            return fallback_result(
                error="json_parse_failed", prompt_hash=prompt_hash, raw_reply=raw_model_reply
            )

    # 4) Validate + coerce into our schema
    normalized: Dict[str, Any] = _validate_and_normalize(parsed_json)
    try:
        label_str = str(normalized.get("label"))
        score_float = float(normalized.get("score", 0.0))
        print(f"[llm] Validation complete | label={label_str} score={score_float}", flush=True)
    except Exception:
        print("[llm] Validation complete", flush=True)

    # Attach meta for traceability/debugging.
    normalized["meta"] = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
        "json_mode": json_mode,
        "prompt_hash": prompt_hash,
        "passages_used": [p.get("doc_id") for p in compacted_passages],
        "prompts": [{"role": m.role, "text": m.text} for m in prompt_messages],
    }

    print("[llm] Classification complete", flush=True)
    return normalized


def _validate_and_normalize(input_obj: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and coerce the model output into the expected schema.

    Parameters
    - input_obj: arbitrary object parsed from the model's JSON response.

    Returns
    - A dict conforming to schema "rexis.llmrag.classification.v1" with safe defaults
      and bounded values.
    """
    normalized: Dict[str, Any] = {
        "schema": "rexis.llmrag.classification.v1",
        "score": 0.0,
        "label": "unknown",
        "classification": [],
        "families": [],
        "capabilities": [],
        "tactics": [],
        "evidence": [],
        "uncertainty": "high",
    }

    try:
        score: float = float(input_obj.get("score", 0.0))
    except Exception:
        score = 0.0
    score = max(0.0, min(1.0, score))
    normalized["score"] = round(score, 4)

    label: str = str(input_obj.get("label", "unknown")).lower()
    if label not in {"malicious", "suspicious", "benign", "unknown"}:
        if score >= SCORE_THRESHOLD_MALICIOUS:
            label = "malicious"
        elif score >= SCORE_THRESHOLD_SUSPICIOUS:
            label = "suspicious"
        elif score <= SCORE_THRESHOLD_BENIGN_MAX:
            label = "benign"
        else:
            label = "unknown"
    normalized["label"] = label

    def _norm_list(values: Any, cast_type=str, limit: int = 16) -> List[Any]:
        """Coerce an iterable to a list of a given type and apply a soft length limit."""
        vals: List[Any] = []
        for v in values or []:
            try:
                vals.append(cast_type(v))
            except Exception:
                continue
            if len(vals) >= limit:
                break
        return vals

    normalized["classification"] = _norm_list(input_obj.get("classification"), str, 6)
    normalized["families"] = _norm_list(input_obj.get("families"), str, 8)
    normalized["capabilities"] = _norm_list(input_obj.get("capabilities"), str, 12)
    normalized["tactics"] = _norm_list(input_obj.get("tactics"), str, 12)

    evidence_in: List[Dict[str, Any]] = input_obj.get("evidence") or []
    evidence_out: List[Dict[str, Any]] = []
    for item in evidence_in[:8]:
        try:
            evidence_out.append(
                {
                    "id": str(item.get("id") or "evidence"),
                    "title": str(item.get("title") or "Evidence"),
                    "detail": str(item.get("detail") or ""),
                    "severity": coerce_severity(item.get("severity")),
                    "source": coerce_source(item.get("source")),
                    "doc_ref": str(item.get("doc_ref") or ""),
                }
            )
        except Exception:
            continue
    normalized["evidence"] = evidence_out

    uncertainty_level: str = str(input_obj.get("uncertainty", "high")).lower()
    if uncertainty_level not in {"low", "medium", "high"}:
        uncertainty_level = "high"
    normalized["uncertainty"] = uncertainty_level

    if isinstance(input_obj.get("notes"), str) and input_obj["notes"].strip():
        normalized["notes"] = input_obj["notes"].strip()

    return normalized
