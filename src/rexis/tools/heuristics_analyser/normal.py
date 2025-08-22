import re
from typing import Dict, Iterable, List, Tuple

from rexis.tools.heuristics_analyser.utils import get_nested_value
from rexis.utils.constants import DEFAULT_NORMALIZATION_RULES


def _default_compiled_rules() -> List[Tuple[re.Pattern[str], str]]:
    """Return default normalization rules with compiled regex patterns.

    Accepts either (str, str) or (Pattern, str) tuples from constants and
    guarantees a compiled Pattern on return.
    """
    compiled: List[Tuple[re.Pattern[str], str]] = []
    for pat, fam in DEFAULT_NORMALIZATION_RULES:
        if isinstance(pat, re.Pattern):
            compiled.append((pat, fam))
        else:
            try:
                compiled.append((re.compile(str(pat), re.I), fam))
            except re.error:
                # Skip invalid default entries defensively
                continue
    return compiled


def _compile_rules_from_config(
    rules_cfg: Dict[str, object] | None,
) -> List[Tuple[re.Pattern[str], str]]:
    """Build normalization rules from heuristics config.

    Expected structure:
    taxonomy:
      normalization_rules:
        - pattern: "regex"
          family: "ransomware"
        - pattern: "..."
          family: "..."
    """
    if not isinstance(rules_cfg, dict):
        return _default_compiled_rules()
    items = get_nested_value(rules_cfg, "taxonomy.normalization_rules", None)
    if not isinstance(items, list) or not items:
        return _default_compiled_rules()
    compiled: List[Tuple[re.Pattern[str], str]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        pat = it.get("pattern")
        fam = it.get("family")
        if not pat or not fam:
            continue
        try:
            rx = re.compile(str(pat), re.I)
            compiled.append((rx, str(fam)))
        except re.error:
            # ignore bad regex entries
            continue
    return compiled or _default_compiled_rules()


def _iter_name_tokens(names: Iterable[str]) -> Iterable[str]:
    for raw in names:
        if not raw:
            continue
        s = str(raw)
        # split on common separators while keeping whole name for broader matching
        yield s
        for t in re.split(r"[^A-Za-z0-9_]+", s):
            if t:
                yield t


def normalize_vendor_names_to_families(
    vendor_names: Iterable[str], rules_cfg: Dict[str, object] | None = None
) -> Dict[str, int]:
    """Map a list of vendor/VT threat names to canonical families with simple counts.

    Returns dict: {family: count}
    """
    compiled_rules = _compile_rules_from_config(rules_cfg)
    counts: Dict[str, int] = {}
    for token in _iter_name_tokens(vendor_names):
        for rx, fam in compiled_rules:
            if rx.search(token):
                counts[fam] = counts.get(fam, 0) + 1
                break
    return counts


def families_from_vt_compact(
    vt: Dict[str, object], rules_cfg: Dict[str, object] | None = None
) -> Dict[str, int]:
    """Extract families from our compact VT record using normalization rules."""
    names: List[str] = []
    val = vt.get("popular_threat_name") if isinstance(vt, dict) else None
    if isinstance(val, list):
        names.extend([str(x) for x in val])
    elif isinstance(val, str):
        # Some values are comma-separated
        names.extend([s.strip() for s in val.split(",") if s.strip()])
    # meaningful_name sometimes encodes family hints (e.g., AgentTesla.exe)
    mn = vt.get("meaningful_name") if isinstance(vt, dict) else None
    if isinstance(mn, str):
        names.append(mn)

    # popular_threat_category may be a list of dicts with 'value'
    cat = vt.get("popular_threat_category") if isinstance(vt, dict) else None
    if isinstance(cat, list):
        for c in cat:
            if isinstance(c, dict) and c.get("value"):
                names.append(str(c["value"]))

    return normalize_vendor_names_to_families(names, rules_cfg=rules_cfg)
