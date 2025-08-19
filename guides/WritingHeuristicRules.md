# Writing Heuristic Rules for REXIS

This guide explains how to author, register, and tune heuristic rules that score binaries in the heuristics analyser pipeline.

## Quick mental model

- Rules are pure functions that inspect a `features: Dict[str, Any]` structure and optionally return an `Evidence` object.
- Evidence has an `id`, `title`, `detail`, `severity` (info|warn|error), and a raw `score` in [0,1].
- Final classification uses a configurable combiner (weighted_sum or max) plus per-rule weights and label thresholds.
- Rules can be allowed/denied, reweighted, or given label overrides via a YAML/JSON config file.

## Data contract: features and evidence

Inputs (subset of `rexis.utils.types.Features` with optional extras):
- `program`: metadata with fields like `name`, `format`, `language`, `compiler`, `image_base`, `size`, `sha256`.
- `functions`: list of function info (name, entry, size, is_thunk, calling_convention?).
- `imports`: list of imported API names (strings).
- `decompiled`: list of decompiled function records (optional, may contain `c` with C-like text).
- Optional: `sections`: list of sections `{ name: str, size: int, flags: ["exec","write", ...] }`.
- Optional: `strings`: list of extracted strings (if available in your pipeline phase).

Helpers in `rexis.tools.heuristics_analyser.utils` make reading these safe:
- `get_imports_set(features) -> Set[str]` (lowercased)
- `get_strings_list(features) -> List[str]`
- `get_sections(features) -> List[Dict[str, Any]]`
- `has_tiny_text_section(features) -> bool`
- `is_entry_section_writable(features) -> Optional[bool]`
- `get_nested_value(features, path, default) -> Any`

Evidence (from `rexis.utils.types.Evidence`):
- `id: str` — unique id for the rule (see wiring below)
- `title: str` — short human-readable name
- `detail: str` — concise explanation with indicators matched
- `severity: str` — `info` | `warn` | `error` (affects filtering of returned evidence, not the combiner math)
- `score: float` — raw strength in [0,1], capped per-rule via config weights

## Authoring a rule (rules.py)

Create a pure function in `src/rexis/tools/heuristics_analyser/rules.py`:

```python
from typing import Any, Dict, Optional, Set
from rexis.tools.heuristics_analyser.utils import get_imports_set
from rexis.utils.types import Evidence

def rule_suspicious_mutex_creation(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = get_imports_set(features)
    mutex_apis = {"createmutexa", "createmutexw", "openmutexa", "openmutexw"}
    hits = imps & mutex_apis
    if not hits:
        return None
    return Evidence(
        id="suspicious_mutex_creation",
        title="Mutex creation/manipulation",
        detail=f"Imports include: {', '.join(sorted(hits))}",
        severity="info",
        score=0.1,
    )
```

Guidelines:
- Always handle missing fields gracefully; prefer helpers and defaults.
- Return `None` if the rule doesn’t fire; never raise.
- Keep `detail` short with key indicators; avoid huge dumps.
- Choose severity by signal confidence (common capabilities => info; strong TTP combos => warn/error).
- Keep scores moderate and let configuration weights shape final impact.

## Wiring a rule (main.py)

Add the import and register it in the `ruleset` list in `src/rexis/tools/heuristics_analyser/main.py`.
The tuple’s first element is the canonical rule id; the engine sets `ev.id` to this value.

```python
from rexis.tools.heuristics_analyser.rules import (
    # ...existing imports...
    rule_suspicious_mutex_creation,
)

ruleset = [
    # ...existing rules...
    ("suspicious_mutex_creation", rule_suspicious_mutex_creation),
]
```

## Tuning weights and thresholds (constants or external file)

Defaults live in `src/rexis/utils/constants.py` under `DEFAULT_HEURISTIC_RULES`.
Key sections:
- `scoring.base`: base score added before evidence.
- `scoring.combine`: `weighted_sum` (default) or `max`.
- `scoring.label_thresholds`: numbers in [0,1] for `malicious` and `suspicious`.
- `weights`: map of `rule_id -> weight` (caps contribution: `min(1.0, ev.score * weight)`).
- `allow_rules` / `deny_rules`: optional white/black lists of rule ids.
- `label_overrides`: `rule_id -> label` to force a label if that rule fires.

You can override defaults at runtime by providing a YAML/JSON rules file to the analyser; it is merged into the defaults.

### Example YAML override

```yaml
scoring:
  base: 0.0
  combine: weighted_sum
  label_thresholds:
    malicious: 0.75
    suspicious: 0.45
weights:
  sus_api_combo: 0.35
  service_persistence: 0.30
  suspicious_mutex_creation: 0.15
allow_rules: []  # run all unless denied
deny_rules:
  - filesystem_mod        # too noisy for our environment
label_overrides:
  ransom_notes: ransomware  # if you add a dedicated rule for ransom notes
```

Use `allow_rules` to run only a subset (whitelist), or `deny_rules` to disable noisy rules.

## Severity and score guidance

- severity controls visibility in the returned evidence (via `min_severity`), not math.
- score is the raw signal strength; weight controls its contribution in the combiner.
- Suggested mapping:
  - info: 0.05–0.15
  - warn: 0.15–0.35
  - error: 0.30–0.60 (keep headroom for strong combinations)

## Best practices

- Deterministic and pure: no I/O, no randomness, no network calls.
- Defensive on missing data: default to safe fallbacks, use helper getters.
- Keep runtime cheap: set operations, basic scans, small regexes.
- Avoid duplication: if a signal already exists (e.g., tiny .text), reuse or complement.
- Use clear ids and titles; ids must be unique across rules.

## Testing a rule quickly (ad hoc)

```python
from rexis.tools.heuristics_analyser.main import heuristic_classify

features = {
  "program": {"name": "sample.exe", "size": 200_000, "sha256": "...", "format": "pe", "language": "x86", "compiler": "msvc", "image_base": "0x400000"},
  "imports": ["CreateMutexA", "GetProcAddress"],
  "sections": [{"name": ".text", "size": 3500, "flags": ["exec", "write"]}],
  "strings": ["http://example.com", "VirtualBox"],
}

result = heuristic_classify(features)
print(result["score"], result["label"])  # and inspect result["evidence"]
```

## Adding helpers

If a rule needs common utilities (e.g., more extractors or normalizers), add them to `utils.py` in the same package to keep rules simple and consistent.

## Checklist for adding a rule

1) Implement `rule_<name>` in `rules.py` and return `Evidence` or `None`.
2) Import and register it in `main.py` with a stable id.
3) Add a default weight in `DEFAULT_HEURISTIC_RULES["weights"]` (constants.py).
4) Document the rule id and intended severity/score in your team notes.
5) (Optional) Provide example YAML overrides for tuning/enablement.

---

If you need examples, see existing rules in `rules.py` (e.g., `rule_suspicious_api_combination`, `rule_packer_artifacts`, `rule_service_persistence`) for patterns and severity/score balance.
