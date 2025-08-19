import ast
import re
from typing import List

import openai
from rexis.utils.config import config
from rexis.utils.utils import LOGGER


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
    max_tokens = getattr(tagger_cfg, "max_tokens", 128)
    try:
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
        try:
            tags_list = ast.literal_eval(content)
            if isinstance(tags_list, list):
                return [str(t).strip() for t in tags_list if isinstance(t, str)]
        except Exception:
            LOGGER.error("Tagger: LLM response is not a valid list: %s", content)
            pass
        # Try to extract a list using regex (e.g., ["tag1", "tag2"])
        match = re.search(r"\[(.*?)\]", content, re.DOTALL)
        if match:
            items = match.group(1)
            # Split by comma, remove quotes and whitespace
            tags = [i.strip().strip("\"'") for i in items.split(",") if i.strip()]
            if tags:
                return tags
        # Fallback: split by commas or lines
        if "," in content:
            tags = [t.strip().strip("\"'") for t in content.split(",") if t.strip()]
            if tags:
                return tags
        tags = [t.strip().strip("\"'") for t in content.splitlines() if t.strip()]
        if tags:
            return tags
        LOGGER.warning("Tagger: LLM did not return a parseable list. Got: %s", content)
        return []
    except Exception as e:
        LOGGER.error(f"Tagger: LLM tagging failed: {e}")
        return []


def tag_chunks_batch(texts: List[str], **kwargs) -> List[str]:
    """
    Tag a batch of text chunks. Returns a list of tag lists (one per chunk).
    """
    results = []
    for text in texts:
        results.append(tag_chunk(text, **kwargs))
    return results
