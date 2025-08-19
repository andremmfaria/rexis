import re
from typing import Any, Dict, List, Optional, Set, Tuple
from rexis.tools.heuristics_analyser.utils import (
    get_imports_set,
    get_strings_list,
    has_tiny_text_section,
    is_entry_section_writable,
    get_nested_value,
)
from rexis.utils.types import Evidence
from rexis.utils.constants import SOCIAL_DOMAINS


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
        "httpopenrequesta",
        "httpsendrequesta",
        "internetopenurla",
        "winhttpopen",
        "winhttpopenrequest",
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


def rule_tiny_text_section(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Dedicated signal when .text section is unusually small (< 4KB).
    Even if covered in packer_artifacts, expose as its own rule for scoring flexibility.
    """
    if not has_tiny_text_section(features):
        return None
    # try to get the exact size if available for nicer detail
    secs: List[Dict[str, Any]] = get_nested_value(features, "sections", []) or []
    size_info: Optional[int] = None
    for s in secs:
        if (s.get("name") or "").lower() in {".text", "text"}:
            try:
                size_info = int(s.get("size") or 0)
            except Exception:
                size_info = None
            break
    detail = "Detected tiny .text section (<4KB)"
    if size_info is not None and size_info > 0:
        detail += f"; size={size_info} bytes"
    return Evidence(
        id="tiny_text_section",
        title="Tiny .text section",
        detail=detail,
        severity="warn",
        score=0.25,
    )


def rule_low_entropy_strings(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Very few or no human-readable strings can indicate packing or heavy obfuscation.
    We treat low string count as a proxy for "low information in strings".
    """
    strings: List[str] = get_strings_list(features)
    total: int = len(strings)
    prog_size: int = int(get_nested_value(features, "program.size", 0) or 0)
    # Heuristic: if program is sizable (>100KB) but has very few strings, flag.
    if prog_size >= 100 * 1024 and total <= 8:
        return Evidence(
            id="low_entropy_strings",
            title="Sparse strings (possible packing)",
            detail=f"Binary size={prog_size} bytes but only {total} extracted strings",
            severity="info",
            score=0.1,
        )
    # Alternatively, if there are strings but most are very short (<4 chars), also weak signal
    short = sum(1 for s in strings if len(s) < 4)
    if total > 0 and short / max(1, total) > 0.8 and prog_size >= 100 * 1024:
        return Evidence(
            id="low_entropy_strings",
            title="Mostly short strings (possible packing)",
            detail=f"{short}/{total} strings <4 chars",
            severity="info",
            score=0.08,
        )
    return None


def rule_dynamic_api_resolution(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    LoadLibrary/GetProcAddress patterns used for late binding and API hashing.
    """
    imps: Set[str] = get_imports_set(features)
    dyn: Set[str] = {"loadlibrarya", "loadlibraryw", "getprocaddress"}
    if imps & dyn:
        return Evidence(
            id="dynamic_api_resolution",
            title="Dynamic API resolution",
            detail=f"Imports include: {', '.join(sorted(imps & dyn))}",
            severity="warn",
            score=0.2,
        )
    return None


def rule_service_persistence(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Windows Service creation/manipulation APIs used for persistence/privileged execution.
    """
    imps: Set[str] = get_imports_set(features)
    svc: Set[str] = {
        "openscmanagera",
        "openscmanagerw",
        "createservicea",
        "createservicew",
        "openservicea",
        "openservicew",
        "startservicea",
        "startservicew",
        "controlservice",
        "deleteservice",
        "changeserviceconfiga",
        "changeserviceconfigw",
    }
    hits = imps & svc
    if hits:
        return Evidence(
            id="service_persistence",
            title="Service manipulation",
            detail=f"Imports include: {', '.join(sorted(hits))}",
            severity="warn",
            score=0.25,
        )
    return None


def rule_filesystem_modification(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Filesystem modification capability. On its own it's common, so low severity unless paired elsewhere.
    """
    imps: Set[str] = get_imports_set(features)
    fs: Set[str] = {
        "createfilea",
        "createfilew",
        "writefile",
        "readfile",
        "deletefilea",
        "deletefilew",
        "copyfilea",
        "copyfilew",
        "movefilea",
        "movefilew",
        "setfileattributesa",
        "setfileattributesw",
    }
    hits = imps & fs
    if hits:
        return Evidence(
            id="filesystem_mod",
            title="Filesystem modification capability",
            detail=f"Imports include: {', '.join(sorted(hits))}",
            severity="info",
            score=0.1,
        )
    return None


def _extract_urls_and_ips(strings: List[str]) -> Tuple[List[str], List[str]]:
    urls: List[str] = []
    ips: List[str] = []
    url_pattern = re.compile(r"https?://[\w\-\.:/%\?=&#]+", re.IGNORECASE)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for s in strings:
        for m in url_pattern.findall(s):
            urls.append(m)
        for m in ip_pattern.findall(s):
            ips.append(m)
    return urls, ips


def rule_suspicious_urls_in_strings(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Detect hard-coded URLs/IPs excluding well-known social domains.
    """
    strings: List[str] = get_strings_list(features)
    urls, ips = _extract_urls_and_ips(strings)
    # Filter out social domains
    filtered_urls: List[str] = []
    for u in urls:
        low = u.lower()
        if any(dom in low for dom in SOCIAL_DOMAINS):
            continue
        filtered_urls.append(u)
    total_hits = len(filtered_urls) + len(ips)
    if total_hits == 0:
        return None
    # Show up to 3 indicators in detail
    preview = filtered_urls[:3] + ips[: max(0, 3 - len(filtered_urls))]
    return Evidence(
        id="suspicious_urls_in_strings",
        title="Embedded external endpoints",
        detail=f"Found {total_hits} URL/IP indicators; e.g., {', '.join(preview)}",
        severity="warn" if total_hits >= 3 else "info",
        score=0.15 if total_hits >= 3 else 0.08,
    )


def rule_anti_vm_strings(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Anti-VM/analysis hints via strings.
    """
    strings: List[str] = [s.lower() for s in get_strings_list(features)]
    tokens: Set[str] = {
        "vbox",
        "virtualbox",
        "vmware",
        "qemu",
        "bochs",
        "sandboxie",
        "cuckoo",
        "wine",
        "xen",
    }
    hits = {t for t in tokens if any(t in s for s in strings)}
    if not hits:
        return None
    return Evidence(
        id="anti_vm_strings",
        title="Anti-VM indicators (strings)",
        detail=f"Tokens: {', '.join(sorted(hits))}",
        severity="warn",
        score=0.15,
    )


def rule_http_exfil_indicators(features: Dict[str, Any]) -> Optional[Evidence]:
    """
    Specific HTTP exfil/POST indicators from WinINet/WinHTTP APIs.
    """
    imps: Set[str] = get_imports_set(features)
    http: Set[str] = {
        "httpsendrequesta",
        "httpsendrequestw",
        "httpaddrequestheadersa",
        "httpaddrequestheadersw",
        "internetwritefile",
        "winhttpsendrequest",
        "winhttpwritedata",
    }
    hits = imps & http
    if hits:
        return Evidence(
            id="http_exfil_indicators",
            title="HTTP request/POST capability",
            detail=f"Imports include: {', '.join(sorted(hits))}",
            severity="warn",
            score=0.2,
        )
    return None
