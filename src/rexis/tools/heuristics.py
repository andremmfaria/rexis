import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable, Tuple
import yaml

from rexis.utils.types import Evidence


SEVERITY_ORDER: Dict[str, int] = {"info": 0, "warn": 1, "error": 2}


def _severity_is_at_least(min_sev: str, sev: str) -> bool:
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(min_sev, 0)


def _get_nested_value(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Safe getter with 'a.b.c' paths.
    """
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _load_heuristic_rules(rules_path: Optional[Path]) -> Dict[str, Any]:
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
        return _default_heuristic_rules()

    text = rules_path.read_text(encoding="utf-8")
    data: Dict[str, Any]
    if rules_path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")

    # Merge with defaults so everything has sane values
    return _merge_rule_configs(_default_heuristic_rules(), data)


def _default_heuristic_rules() -> Dict[str, Any]:
    # Tunable defaults for baseline
    return {
        "scoring": {
            "base": 0.0,
            "combine": "weighted_sum",  # or "max"
            "label_thresholds": {
                "malicious": 0.70,
                "suspicious": 0.40,
                "benign": 0.0,
            },
        },
        "weights": {
            # weights cap each rule's score contribution
            "sus_api_combo": 0.30,
            "packer_artifacts": 0.25,
            "entry_in_writable": 0.20,
            "low_entropy_strings": 0.10,
            "networking_indicators": 0.20,
            "crypto_indicators": 0.15,
            "shell_exec_indicators": 0.25,
            "autorun_persistence": 0.20,
            "dbg_anti_dbg": 0.20,
            "tiny_text_section": 0.15,
        },
        # Optional allow/deny lists
        "allow_rules": [],
        "deny_rules": [],
        # Optional explicit label overrides by rule hits (rule_id -> label)
        "label_overrides": {
            # Example: if "ransom_notes" fires, force label
            # "ransom_notes": "ransomware"
        },
    }


def _merge_rule_configs(base: Dict[str, Any], ext: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (ext or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_rule_configs(out[k], v)
        else:
            out[k] = v
    return out


def _is_rule_enabled(rule_id: str, rules: Dict[str, Any]) -> bool:
    allow: List[str] = rules.get("allow_rules") or []
    deny: List[str] = rules.get("deny_rules") or []
    if allow and rule_id not in allow:
        return False
    if deny and rule_id in deny:
        return False
    return True


def _get_imports_set(features: Dict[str, Any]) -> Set[str]:
    imps: List[Any] = _get_nested_value(features, "imports", []) or []
    return {i.lower() for i in imps if isinstance(i, str)}


def _get_strings_list(features: Dict[str, Any]) -> List[str]:
    # If you later add strings to features["strings"]
    return [s for s in _get_nested_value(features, "strings", []) if isinstance(s, str)]


def _get_sections(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _get_nested_value(features, "sections", [])


def _is_entry_section_writable(features: Dict[str, Any]) -> Optional[bool]:
    """
    If features include sections with flags and entry RVA, detect if entry lies in a writable section.
    Expected shape (optional):
      features["sections"] = [{ "name": ".text", "start": ..., "end": ..., "flags": ["exec","write"]}, ...]
      features["program"]["image_base"] in hex string
      functions[0]['entry'] may equal program entrypoint when name == 'entry' or similar
    This baseline uses a heuristic fallback: if a section named '.text' is missing 'exec', or entry function's
    section has 'write'.
    """
    secs: List[Dict[str, Any]] = _get_sections(features)
    if not secs:
        return None
    # Very rough check: any executable section marked writable?
    for s in secs:
        flags: Set[str] = set((s.get("flags") or []))
        if "exec" in flags and "write" in flags:
            return True
    return False


def rule_suspicious_api_combination(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Suspicious API combinations frequently used by droppers/injectors:
    - CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, NtUnmapViewOfSection
    - URLDownloadToFileA/W, WinHttpOpenRequest, InternetOpenUrl
    - RegSetValue, RegCreateKey (persistence-ish but weaker signal)
    """
    imps: Set[str] = _get_imports_set(features)
    inj: Set[str] = {
        "createremotethread",
        "virtualallocex",
        "writeprocessmemory",
        "ntunmapviewofsection",
    }
    net: Set[str] = {
        "urldownloadtofilea",
        "urldownloadtofilew",
        "winhttpopenrequest",
        "internetopenurla",
        "internetopenurlw",
    }
    reg: Set[str] = {"regsetvaluea", "regsetvaluew", "regcreatekeya", "regcreatekeyw"}

    score: float = 0.0
    hit_sets: List[str] = []
    if inj & imps:
        score += 0.5
        hit_sets.append("process-injection")
    if net & imps:
        score += 0.3
        hit_sets.append("networking")
    if reg & imps:
        score += 0.2
        hit_sets.append("registry")

    if score == 0.0:
        return None
    return Evidence(
        id="sus_api_combo",
        title="Suspicious API combination",
        detail=f"Hits: {', '.join(hit_sets)}",
        severity="error" if score >= 0.5 else "warn",
        score=min(1.0, score),
    )


def rule_packer_artifacts(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Packer/obfuscation hints: presence of imports like 'LoadResource', 'FindResource',
    extremely small .text, or known packer strings (UPX, MPRESS, ASPack).
    """
    imps: Set[str] = _get_imports_set(features)
    strings: List[str] = [s.lower() for s in _get_strings_list(features)]
    packer_tokens: Set[str] = {"upx", "mpress", "aspack", "petite", "themida"}

    hits: List[str] = []
    if any(tok in (strings or []) for tok in packer_tokens):
        hits.append("packer-string")
    res_apis: Set[str] = {"loadresource", "findresource", "lockresource"}
    if res_apis & imps:
        hits.append("resource-packaging")

    tiny_text: bool = _has_tiny_text_section(features)
    if tiny_text:
        hits.append("tiny-.text")

    if not hits:
        return None
    sev: str = "warn" if "tiny-.text" in hits else "info"
    return Evidence(
        id="packer_artifacts",
        title="Packer / obfuscation indicators",
        detail=f"Signals: {', '.join(hits)}",
        severity=sev,
        score=0.4 if "tiny-.text" in hits else 0.2,
    )


def _has_tiny_text_section(features: Dict[str, Any]) -> bool:
    """
    Very rough heuristic when sections metadata is available:
      - .text smaller than 4KB can be suspicious for PE (packed/loader stubs)
    If sections are absent, returns False.
    """
    secs: List[Dict[str, Any]] = _get_sections(features)
    if not secs:
        return False
    for s in secs:
        name: str = (s.get("name") or "").lower()
        size: int = s.get("size") or 0
        if name in {".text", "text"} and isinstance(size, int) and size > 0 and size < 4096:
            return True
    return False


def rule_entry_in_writable_section(features: Dict[str, Any]) -> Optional[Evidence]:
    w: Optional[bool] = _is_entry_section_writable(features)
    if w is None or w is False:
        return None
    return Evidence(
        id="entry_in_writable",
        title="Entrypoint in writable/executable section",
        detail="Entry section has both EXECUTE and WRITE permissions.",
        severity="error",
        score=0.6,
    )


def rule_networking_indicators(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = _get_imports_set(features)
    net: Set[str] = {
        "wsastartup",
        "wsasocketa",
        "connect",
        "send",
        "recv",
        "internetopena",
        "internetconnecta",
        "internetreadfile",
    }
    if imps & net:
        return Evidence(
            id="networking_indicators",
            title="Networking-capable binary",
            detail=f"Imports include: {', '.join(sorted(imps & net))}",
            severity="warn",
            score=0.25,
        )
    return None


def rule_crypto_indicators(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = _get_imports_set(features)
    crypto: Set[str] = {
        "cryptacquirecontexta",
        "cryptencrypt",
        "cryptdecrypt",
        "bcryptgenrandom",
        "bcryptencrypt",
        "bcryptdecrypt",
    }
    if imps & crypto:
        return Evidence(
            id="crypto_indicators",
            title="Cryptographic API usage",
            detail=f"Imports include: {', '.join(sorted(imps & crypto))}",
            severity="warn",
            score=0.2,
        )
    return None


def rule_shell_execution_indicators(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = _get_imports_set(features)
    shell: Set[str] = {"winexec", "shellexecutea", "shellexecutew", "system"}
    if imps & shell:
        return Evidence(
            id="shell_exec_indicators",
            title="Shell execution capability",
            detail=f"Imports include: {', '.join(sorted(imps & shell))}",
            severity="error",
            score=0.35,
        )
    return None


def rule_autorun_persistence(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = _get_imports_set(features)
    reg: Set[str] = {
        "regsetvaluea",
        "regsetvaluew",
        "regcreatekeya",
        "regcreatekeyw",
        "regopenkeya",
        "regopenkeyw",
    }
    if imps & reg:
        return Evidence(
            id="autorun_persistence",
            title="Potential persistence via registry",
            detail=f"Registry APIs present: {', '.join(sorted(imps & reg))}",
            severity="warn",
            score=0.25,
        )
    return None


def rule_debugger_anti_debug_indicators(features: Dict[str, Any]) -> Optional[Evidence]:
    imps: Set[str] = _get_imports_set(features)
    dbg: Set[str] = {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "outputdebugstringa",
        "outputdebugstringw",
    }
    if imps & dbg:
        return Evidence(
            id="dbg_anti_dbg",
            title="Debugger/anti-debug indicators",
            detail=f"Imports include: {', '.join(sorted(imps & dbg))}",
            severity="warn",
            score=0.2,
        )
    return None


def _combine_evidence_score(evidence: List[Evidence], rules: Dict[str, Any]) -> float:
    base: float = float(_get_nested_value(rules, "scoring.base", 0.0) or 0.0)
    weights: Dict[str, Any] = rules.get("weights") or {}
    mode: str = (
        _get_nested_value(rules, "scoring.combine", "weighted_sum") or "weighted_sum"
    ).lower()

    if mode == "max":
        best: float = 0.0
        for ev in evidence:
            if ev.id in weights:
                best = max(best, min(1.0, ev.score * float(weights.get(ev.id, 1.0))))
        return max(0.0, min(1.0, base if best == 0 else best))

    # default: weighted_sum with cap at 1.0
    total: float = base
    for ev in evidence:
        w: float = float(weights.get(ev.id, 0.0))
        if w <= 0.0:
            continue
        total += min(1.0, ev.score * w)
    return max(0.0, min(1.0, total))


def _label_from_combined_score(score: float, rules: Dict[str, Any], overrides: List[str]) -> str:
    # explicit rule-based overrides first
    label_over: Dict[str, Any] = rules.get("label_overrides") or {}
    for rid in overrides:
        if rid in label_over:
            return str(label_over[rid])

    thr: Dict[str, Any] = _get_nested_value(rules, "scoring.label_thresholds", {}) or {}
    if score >= float(thr.get("malicious", 0.7)):
        return "malicious"
    if score >= float(thr.get("suspicious", 0.4)):
        return "suspicious"
    return "benign"


def heuristic_classify(
    features: Dict[str, Any],
    rules_path: Optional[Path] = None,
    min_severity: str = "info",
) -> Dict[str, Any]:
    """
    Evaluate heuristic rules over decompiler features and return:
    {
      "schema": "rexis.baseline.heuristics.v1",
      "score": 0.73,
      "label": "malicious",
      "evidence": [
        {"id":"...", "title":"...", "detail":"...", "severity":"warn", "score": 0.2}
      ],
      "counts": {"info": 1, "warn": 2, "error": 1}
    }
    """
    rules: Dict[str, Any] = _load_heuristic_rules(rules_path)

    # Collect evidence from built-in rules
    ruleset: List[Tuple[str, Callable[[Dict[str, Any]], Optional[Evidence]]]] = [
        ("sus_api_combo", rule_suspicious_api_combination),
        ("packer_artifacts", rule_packer_artifacts),
        ("entry_in_writable", rule_entry_in_writable_section),
        ("networking_indicators", rule_networking_indicators),
        ("crypto_indicators", rule_crypto_indicators),
        ("shell_exec_indicators", rule_shell_execution_indicators),
        ("autorun_persistence", rule_autorun_persistence),
        ("dbg_anti_dbg", rule_debugger_anti_debug_indicators),
    ]

    all_ev: List[Evidence] = []
    for rid, rule_fn in ruleset:
        if not _is_rule_enabled(rid, rules):
            continue
        ev: Optional[Evidence] = rule_fn(features)
        if ev:
            # Ensure the evidence id matches the configured rule id
            ev.id = rid
            all_ev.append(ev)

    # Combine + label
    score: float = _combine_evidence_score(all_ev, rules)
    override_hits: List[str] = [ev.id for ev in all_ev]
    label: str = _label_from_combined_score(score, rules, override_hits)

    # Filter evidence by min severity for the *returned* payload (score is computed on full set)
    returned_ev: List[Evidence] = [
        ev for ev in all_ev if _severity_is_at_least(min_severity, ev.severity)
    ]
    counts: Dict[str, int] = {"info": 0, "warn": 0, "error": 0}
    for ev in returned_ev:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1

    result: Dict[str, Any] = {
        "schema": "rexis.baseline.heuristics.v1",
        "score": round(float(score), 4),
        "label": label,
        "evidence": [
            {
                "id": ev.id,
                "title": ev.title,
                "detail": ev.detail,
                "severity": ev.severity,
                "score": round(float(ev.score), 4),
            }
            for ev in returned_ev
        ],
        "counts": counts,
    }
    return result
