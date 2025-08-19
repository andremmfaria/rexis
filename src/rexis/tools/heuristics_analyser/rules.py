from typing import Any, Dict, List, Optional, Set
from rexis.tools.heuristics_analyser.utils import (
    get_imports_set,
    get_strings_list,
    has_tiny_text_section,
    is_entry_section_writable,
)
from rexis.utils.types import Evidence


def rule_entry_in_writable_section(features: Dict[str, Any]) -> Optional[Evidence]:
    w: Optional[bool] = is_entry_section_writable(features)
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
    imps: Set[str] = get_imports_set(features)
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
    imps: Set[str] = get_imports_set(features)
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
    imps: Set[str] = get_imports_set(features)
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
    imps: Set[str] = get_imports_set(features)
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
    imps: Set[str] = get_imports_set(features)
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


def rule_packer_artifacts(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Packer/obfuscation hints: presence of imports like 'LoadResource', 'FindResource',
    extremely small .text, or known packer strings (UPX, MPRESS, ASPack).
    """
    imps: Set[str] = get_imports_set(features)
    strings: List[str] = [s.lower() for s in get_strings_list(features)]
    packer_tokens: Set[str] = {"upx", "mpress", "aspack", "petite", "themida"}

    hits: List[str] = []
    if any(tok in (strings or []) for tok in packer_tokens):
        hits.append("packer-string")
    res_apis: Set[str] = {"loadresource", "findresource", "lockresource"}
    if res_apis & imps:
        hits.append("resource-packaging")

    tiny_text: bool = has_tiny_text_section(features)
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


def rule_suspicious_api_combination(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Suspicious API combinations frequently used by droppers/injectors:
    - CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, NtUnmapViewOfSection
    - URLDownloadToFileA/W, WinHttpOpenRequest, InternetOpenUrl
    - RegSetValue, RegCreateKey (persistence-ish but weaker signal)
    """
    imps: Set[str] = get_imports_set(features)
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
