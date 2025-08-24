# Writing Heuristic Rules for REXIS

This guide explains how to author, register, and tune heuristic rules that score binaries in the heuristics analyser pipeline.

## Quick mental model

- Rules are pure functions that inspect a `features: Dict[str, Any]` structure and return a tuple `(Evidence|None, reason|None)`.
  - Signature now accepts tuning inputs: `(features, rule_score: float = <default>, params: Dict[str, Any] = {})`.
  - On hit, return `(Evidence, "short reason")`. Use `rule_score`/`params` to scale and tune internals.
  - On miss, return `(None, "miss reason")` so the engine can log why.
- Evidence has `id`, `title`, `detail`, `severity` (info|warn|error), and a raw `score` in [0,1]. In results, hits also include `reason` and per-evidence `categories` derived from the tagging map.
- Final classification uses a configurable combiner (`weighted_sum` or `max`) plus per-rule weights and label thresholds.
- Rules can be allowed/denied, reweighted, given per-rule args via `rule_args`, or label overrides via a YAML/JSON config file (merged with defaults at load time).
- The analyser infers tags with per-tag scores via a configurable `tagging` section and returns a short `classification` list of top tag names.
- Vendor names from VirusTotal can be normalized to canonical families using configurable `taxonomy.normalization_rules`.

## Data contract: features and evidence

Inputs (subset of `rexis.utils.types.Features` with optional extras):
- `program`: metadata with fields like `name`, `format`, `language`, `compiler`, `image_base`, `size`, `sha256`.
- `functions`: list of function info (name, entry, size, is_thunk, calling_convention?).
- `imports`: list of imported API names (strings).
- `decompiled`: list of decompiled function records (optional, may contain `c` with C-like text).
- Optional: `sections`: list of sections `{ name: str, size: int, flags: ["exec","write", ...] }`.
- Optional: `strings`: list of extracted strings (if available in your pipeline phase).

Helpers in `rexis.tools.heuristics_analyser.utils` make reading these safe:
- `get_imports_set(features) -> Set[str>` (lowercased)
- `get_strings_list(features) -> List[str]`
- `get_sections(features) -> List[Dict[str, Any]]`
- `has_tiny_text_section(features) -> bool`
- `is_entry_section_writable(features) -> Optional[bool]`
- `get_nested_value(features, path, default) -> Any`
- `severity_is_at_least(min, sev) -> bool`
- `load_heuristic_rules(path) -> Dict[str, Any]` (merges YAML/JSON with defaults)

Evidence (from `rexis.utils.types.Evidence`):
- `id: str` — unique id for the rule (see wiring below)
- `title: str` — short human-readable name
- `detail: str` — concise explanation with indicators matched
- `severity: str` — `info` | `warn` | `error` (affects filtering of returned evidence, not the combiner math)
- `score: float` — raw strength in [0,1], capped per-rule via config weights

## Authoring a rule (rules.py)

Create a pure function in `src/rexis/tools/heuristics_analyser/rules.py` with the new signature:

```python
from typing import Any, Dict, Optional, Set, Tuple
from rexis.tools.heuristics_analyser.utils import get_imports_set
from rexis.utils.types import Evidence

def rule_suspicious_mutex_creation(
  features: Dict[str, Any], rule_score: float = 0.10, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
  imps: Set[str] = get_imports_set(features)
  mutex_apis = {"createmutexa", "createmutexw", "openmutexa", "openmutexw"}
  hits = imps & mutex_apis
  if not hits:
    return None, "no mutex-related imports found"
  # Use the provided rule_score to scale the raw evidence score
  return (
    Evidence(
      id="suspicious_mutex_creation",  # engine will overwrite when wiring
      title="Mutex creation/manipulation",
      detail=f"Imports include: {', '.join(sorted(hits))}",
      severity="info",
      score=float(rule_score),
    ),
    f"matched mutex imports: {', '.join(sorted(hits))}",
  )
```

Guidelines:
- Always handle missing fields gracefully; prefer helpers and defaults.
- Always return a 2-tuple: on miss `(None, reason)`; on hit `(Evidence, brief_reason)`; never raise.
- Keep `detail` short with key indicators; avoid huge dumps.
- Choose severity by signal confidence (common capabilities => info; strong TTP combos => warn/error).
- Keep scores moderate and let configuration weights shape final impact.

## Wiring a rule (main.py)

Add the import and register it in the `ruleset` list in `src/rexis/tools/heuristics_analyser/main.py`.
The tuple’s first element is the canonical rule id; the engine sets `ev.id` to this value and preserves your reason in the output. At runtime, per-rule score and params can be passed via `rule_args` in the config (see below).

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
- `rule_args`: map of `rule_id -> (rule_score, params)` to pass per-rule tuning inputs to your rule implementation.
- `allow_rules` / `deny_rules`: optional white/black lists of rule ids.
- `label_overrides`: `rule_id -> label` to force a label if that rule fires.

You can override defaults at runtime by providing a YAML/JSON rules file to the analyser; it is merged into the defaults.

Notes:
- In `max` mode, `base` acts as a floor only when there are no rule hits; otherwise the maximum weighted rule contribution is used.
- `label_overrides` are applied first: if any hit rule id is present in `label_overrides`, its label wins regardless of score.

Tip: if a rule exists in code but you omit it from `rule_args`, the engine uses a conservative default `(rule_score=0.2, params={})`.

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

## Tagging: inferring malware family/capability tags

The heuristics analyser derives tag candidates with scores in [0,1] from the evidence it collects. This is fully configurable via a `tagging` section in your rules file.

Key parts of the configuration:
- `tagging.map`: maps `rule_id` to one or more `{ tag: weight }`. When a rule fires, its evidence score is multiplied by the tag weight (and optional global tag weight) and accumulated for that tag. Per-tag totals are capped at 1.0.
- `tagging.tag_weights`: optional global multipliers per tag.
- `tagging.threshold`: minimum tag score to include in the output list (default 0.3).
- `tagging.top_k`: maximum number of tags to return (default 5).
- `tagging.evidence_top_k`: how many category hints to include per evidence (default 3).
- `tagging.classification_top_k`: how many top tag names to list in the top-level `classification` field (default 3). If no tag passes the threshold but scores exist, the top few are returned as a fallback.

There is a built-in fallback mapping `DEFAULT_TAG_SCORES` in `src/rexis/utils/constants.py`. If `tagging.map` is omitted, that default will be used. You can globally emphasize/de-emphasize tags with `tagging.tag_weights`.

### Example YAML (tagging section)

```yaml
tagging:
  map:
    networking_indicators:
      trojan: 0.5
      backdoor: 0.5
      botnet: 0.3
    http_exfil_indicators:
      stealer: 0.7
      spyware: 0.6
      exfiltration: 0.8
    filesystem_mod:
      ransomware: 0.7
      wiper: 0.6
      dropper: 0.4
    autorun_persistence:
      persistence: 0.8
      trojan: 0.3
    service_persistence:
      persistence: 0.8
      backdoor: 0.4
    packer_artifacts:
      packed: 0.9
      obfuscated: 0.6
    dynamic_api_resolution:
      obfuscated: 0.7
      packed: 0.4
    crypto_indicators:
      crypto_malware: 0.7
      ransomware: 0.5
  tag_weights:
    ransomware: 1.2   # emphasize ransomware signals overall
    persistence: 0.8  # de-emphasize persistence-only signals
  threshold: 0.35
  top_k: 5
```

### Output shape

The analyser returns a compact result with scoring, evidence, tags, and traceability:

```jsonc
{
  "schema": "rexis.baseline.heuristics.v1",
  "score": 0.73,
  "label": "malicious",
  "evidence": [
    {
      "id": "sus_api_combo",
      "title": "Suspicious API combination",
      "detail": "Hits: process-injection, networking",
      "severity": "error",
      "score": 0.8,
    "reason": "hit sets: process-injection, networking",
    "categories": [ { "tag": "trojan", "score": 0.28 }, { "tag": "backdoor", "score": 0.21 } ]
    }
  ],
  "counts": { "info": 1, "warn": 2, "error": 1 },
  "tags": [ { "tag": "ransomware", "score": 0.61 } ],
  "classification": ["ransomware", "packed", "persistence"],
  "rule_misses": [ { "id": "low_entropy_strings", "reason": "program size below threshold (<100KB) for this heuristic" } ]
}
```

Notes:
- Evidence is filtered by `min_severity` for the returned payload only; scoring always considers all hits.
- Tags are sorted by score (desc), filtered by `threshold`, limited by `top_k`.

## Taxonomy normalization: harmonizing vendor names

To consolidate VirusTotal (and other vendor) names into canonical families, define regex-based rules in your heuristics config under `taxonomy.normalization_rules`. The rules are applied in order (first match wins) over tokens derived from VT fields like `popular_threat_name`, `meaningful_name`, and `popular_threat_category.value`.

If not provided, a sensible default set is used from `src/rexis/utils/constants.py` (see `DEFAULT_NORMALIZATION_RULES`) and applied by the normalization utilities in `src/rexis/tools/heuristics_analyser/normal.py`.

### Example YAML (taxonomy section)

```yaml
taxonomy:
  normalization_rules:
    - pattern: "ransom|locker|crypt(?!o)|cryptolocker|encrypt"
      family: "ransomware"
    - pattern: "(steal|stealer|azoru?lt|redline|vidar|raccoon)"
      family: "stealer"
    - pattern: "backdoor|bdoor|\\brat\\b|remote access trojan"
      family: "backdoor"
    - pattern: "(bank|banload)"
      family: "banker"
    - pattern: "(downloader|dldr)\\b"
      family: "downloader"
    - pattern: "dropper"
      family: "dropper"
    - pattern: "loader"
      family: "loader"
    - pattern: "(botnet|\\bbot\\b)"
      family: "bot"
    - pattern: "(pua|pup|riskware)"
      family: "riskware"
    - pattern: "(spy|spyware)"
      family: "spyware"
    - pattern: "keylog"
      family: "keylogger"
    - pattern: "(miner|xmrig)"
      family: "miner"
    - pattern: "wiper"
      family: "wiper"
    - pattern: "worm"
      family: "worm"
    - pattern: "rootkit"
      family: "rootkit"
    - pattern: "trojan"
      family: "trojan"
```

The baseline pipeline uses these rules to add a `taxonomy.families` section to the final report, counting occurrences per canonical family. You can extend or reorder rules to suit your environment.

## Decision fusion: configuring the final verdict

The baseline pipeline fuses the heuristics score/label with VirusTotal signals to produce a final decision. This fusion is configurable via a `decision` section in the same heuristics rules file (see `DEFAULT_DECISION` in `constants.py`).

Config keys:
- `decision.weights`: relative influence of heuristics vs VirusTotal. Expected keys: `w_h` and `w_vt` in [0,1].
- `decision.thresholds`: final decision thresholds in [0,1] for `malicious` and `suspicious`.
- `decision.policy`: tuning knobs for fusion behavior (currently `gap_penalty_start` to penalize disagreement).

Defaults live in `src/rexis/utils/constants.py` under `DEFAULT_DECISION` and are used when a key is omitted.

Example YAML (decision section):

```yaml
decision:
  weights:
    w_h: 0.5   # heuristics weight
    w_vt: 0.5  # VirusTotal weight
  thresholds:
    malicious: 0.70
    suspicious: 0.40
  policy:
    gap_penalty_start: 0.35
```

Output in the baseline report includes `decision` and a consolidated `final` object, for example:

```jsonc
{
  "decision": { "score": 0.73, "label": "malicious" },
  "final":    { "score": 0.73, "label": "malicious" }
}
```

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
print(result.get("tags", []))             # list of {"tag": str, "score": float}
print(result.get("rule_misses", []))      # list of {"id": str, "reason": str}
```

## Adding helpers

If a rule needs common utilities (e.g., more extractors or normalizers), add them to `utils.py` in the same package to keep rules simple and consistent.

## Checklist for adding a rule

1) Implement `rule_<name>` in `rules.py` and return `Evidence` or `None`.
2) Import and register it in `main.py` with a stable id.
3) Add a default weight in `DEFAULT_HEURISTIC_RULES["weights"]` (constants.py).
4) Document the rule id and intended severity/score in your team notes.
5) (Optional) Provide example YAML overrides for tuning/enablement.

Tip: include clear hit/miss reasons — they’re surfaced in `evidence.reason` and `rule_misses` for easier tuning.

---

If you need examples, see existing rules in `rules.py` (e.g., `rule_suspicious_api_combination`, `rule_packer_artifacts`, `rule_service_persistence`, `rule_suspicious_function_names`) for patterns and severity/score balance.

## Complete example configuration

Below is a full YAML example combining scoring, rule weights, overrides, tagging, and taxonomy normalization in one file.

```yaml
# Heuristics scoring and rule control
scoring:
  base: 0.0
  combine: weighted_sum   # or "max"
  label_thresholds:
    malicious: 0.70
    suspicious: 0.40

# Decision fusion (heuristics + VirusTotal)
decision:
  weights:
    w_h: 0.5
    w_vt: 0.5
  thresholds:
    malicious: 0.70
    suspicious: 0.40
  policy:
    gap_penalty_start: 0.35

# Per-rule weights (caps contribution: min(1.0, ev.score * weight))
weights:
  sus_api_combo: 0.30
  packer_artifacts: 0.25
  tiny_text_section: 0.20
  entry_in_writable: 0.20
  low_entropy_strings: 0.10
  networking_indicators: 0.20
  http_exfil_indicators: 0.20
  crypto_indicators: 0.15
  dynamic_api_resolution: 0.15
  shell_exec_indicators: 0.25
  autorun_persistence: 0.20
  service_persistence: 0.20
  filesystem_mod: 0.10
  suspicious_urls_in_strings: 0.15
  anti_vm_strings: 0.10
  dbg_anti_dbg: 0.20

# Optional allow/deny lists (ids from main.py ruleset)
allow_rules: []
deny_rules: []

# Optional label overrides (force a label if a rule fires)
label_overrides:
  # ransom_notes: ransomware

# Tagging: infer probable malware tags from evidence
tagging:
  map:
    networking_indicators:
      trojan: 0.5
      backdoor: 0.5
      botnet: 0.3
    http_exfil_indicators:
      stealer: 0.7
      spyware: 0.6
      exfiltration: 0.8
    filesystem_mod:
      ransomware: 0.7
      wiper: 0.6
      dropper: 0.4
    autorun_persistence:
      persistence: 0.8
      trojan: 0.3
    service_persistence:
      persistence: 0.8
      backdoor: 0.4
    packer_artifacts:
      packed: 0.9
      obfuscated: 0.6
    tiny_text_section:
      packed: 0.6
    low_entropy_strings:
      packed: 0.4
    entry_in_writable:
      loader: 0.5
      packed: 0.4
    dynamic_api_resolution:
      obfuscated: 0.7
      packed: 0.4
    crypto_indicators:
      crypto_malware: 0.7
      ransomware: 0.5
    sus_api_combo:
      trojan: 0.4
      backdoor: 0.3
      stealer: 0.3
  tag_weights:
    ransomware: 1.1
    persistence: 0.9
  threshold: 0.35
  top_k: 5

# Taxonomy: vendor name normalization to canonical families
taxonomy:
  normalization_rules:
    - pattern: "ransom|locker|crypt(?!o)|cryptolocker|encrypt"
      family: "ransomware"
    - pattern: "(steal|stealer|azoru?lt|redline|vidar|raccoon)"
      family: "stealer"
    - pattern: "backdoor|bdoor|\\brat\\b|remote access trojan"
      family: "backdoor"
    - pattern: "(bank|banload)"
      family: "banker"
    - pattern: "(downloader|dldr)\\b"
      family: "downloader"
    - pattern: "dropper"
      family: "dropper"
    - pattern: "loader"
      family: "loader"
    - pattern: "(botnet|\\bbot\\b)"
      family: "bot"
    - pattern: "(pua|pup|riskware)"
      family: "riskware"
    - pattern: "(spy|spyware)"
      family: "spyware"
    - pattern: "keylog"
      family: "keylogger"
    - pattern: "(miner|xmrig)"
      family: "miner"
    - pattern: "wiper"
      family: "wiper"
    - pattern: "worm"
      family: "worm"
    - pattern: "rootkit"
      family: "rootkit"
    - pattern: "trojan"
      family: "trojan"
```
