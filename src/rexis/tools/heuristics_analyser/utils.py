import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from rexis.utils.constants import DEFAULT_HEURISTIC_RULES

SEVERITY_ORDER: Dict[str, int] = {"info": 0, "warn": 1, "error": 2}


def severity_is_at_least(min_sev: str, sev: str) -> bool:
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(min_sev, 0)


def get_nested_value(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Safe getter with 'a.b.c' paths.
    """
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def load_heuristic_rules(rules_path: Optional[Path]) -> Dict[str, Any]:
    """
    Load rules from YAML or JSON. If none provided, returns defaults.
    Structure:
      scoring:
        base: 0.0
        combine: weighted_sum|max
        label_thresholds:
          malicious: 0.7
          suspicious: 0.4
      weights: {rule_id: weight}
      allow_rules: [ids]  # optional whitelist
      deny_rules: [ids]   # optional blacklist
    """
    if not rules_path:
        return DEFAULT_HEURISTIC_RULES

    text = rules_path.read_text(encoding="utf-8")
    data: Dict[str, Any]
    if rules_path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")

    # Merge with defaults so everything has sane values
    return merge_rule_configs(DEFAULT_HEURISTIC_RULES, data)


def merge_rule_configs(base: Dict[str, Any], ext: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (ext or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_rule_configs(out[k], v)
        else:
            out[k] = v
    return out


def is_rule_enabled(rule_id: str, rules: Dict[str, Any]) -> bool:
    allow: List[str] = rules.get("allow_rules") or []
    deny: List[str] = rules.get("deny_rules") or []
    if allow and rule_id not in allow:
        return False
    if deny and rule_id in deny:
        return False
    return True


def get_imports_set(features: Dict[str, Any]) -> Set[str]:
    imps: List[Any] = get_nested_value(features, "imports", []) or []
    return {i.lower() for i in imps if isinstance(i, str)}


def get_strings_list(features: Dict[str, Any]) -> List[str]:
    vals = get_nested_value(features, "strings", [])
    if not isinstance(vals, list):
        return []
    out: List[str] = []
    for s in vals:
        if isinstance(s, str):
            try:
                out.append(s)
            except Exception:
                pass
    return out


def get_sections(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    return get_nested_value(features, "sections", [])


def is_entry_section_writable(features: Dict[str, Any]) -> Optional[bool]:
    """
    If features include sections with flags and entry RVA, detect if entry lies in a writable section.
    Expected shape (optional):
      features["sections"] = [{ "name": ".text", "start": ..., "end": ..., "flags": ["exec","write"]}, ...]
      features["program"]["image_base"] in hex string
      functions[0]['entry'] may equal program entrypoint when name == 'entry' or similar
    This baseline uses a heuristic fallback: if a section named '.text' is missing 'exec', or entry function's
    section has 'write'.
    """
    secs: List[Dict[str, Any]] = get_sections(features)
    if not secs:
        return None
    # Very rough check: any executable section marked writable?
    for s in secs:
        flags: Set[str] = set((s.get("flags") or []))
        if "exec" in flags and "write" in flags:
            return True
    return False


def has_tiny_text_section(features: Dict[str, Any]) -> bool:
    """
    Very rough heuristic when sections metadata is available:
      - .text smaller than 4KB can be suspicious for PE (packed/loader stubs)
    If sections are absent, returns False.
    """
    secs: List[Dict[str, Any]] = get_sections(features)
    if not secs:
        return False
    for s in secs:
        name: str = (s.get("name") or "").lower()
        size: int = s.get("size") or 0
        if name in {".text", "text"} and isinstance(size, int) and size > 0 and size < 4096:
            return True
    return False
