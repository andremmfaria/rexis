import re
from typing import Any, Dict, List, Optional, Set, Tuple

from rexis.tools.heuristics_analyser.utils import (
    get_imports_set,
    get_nested_value,
    get_strings_list,
    has_tiny_text_section,
    is_entry_section_writable,
)
from rexis.utils.constants import SOCIAL_DOMAINS
from rexis.utils.types import Evidence


def _match_imports_substring(imps: Set[str], tokens: Set[str]) -> Set[str]:
    if not imps or not tokens:
        return set()
    toks = {t.lower() for t in tokens}
    return {imp for imp in imps if any(t in imp for t in toks)}


def rule_entry_in_writable_section(
    features: Dict[str, Any], rule_score: float = 0.60, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    w: Optional[bool] = is_entry_section_writable(features)
    if w is None:
        return None, "no sections metadata available"
    if w is False:
        return None, "no executable section marked writable"
    return (
        Evidence(
            id="entry_in_writable",
            title="Entrypoint in writable/executable section",
            detail="Entry section has both EXECUTE and WRITE permissions.",
            severity="error",
            score=float(rule_score),
        ),
        "entry section is writable and executable",
    )


def rule_networking_indicators(
    features: Dict[str, Any], rule_score: float = 0.25, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
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
    matches = _match_imports_substring(imps, net)
    if matches:
        return (
            Evidence(
                id="networking_indicators",
                title="Networking-capable binary",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched networking imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no networking-related imports found")


def rule_crypto_indicators(
    features: Dict[str, Any], rule_score: float = 0.20, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    imps: Set[str] = get_imports_set(features)
    crypto: Set[str] = {
        "cryptacquirecontexta",
        "cryptencrypt",
        "cryptdecrypt",
        "bcryptgenrandom",
        "bcryptencrypt",
        "bcryptdecrypt",
    }
    matches = _match_imports_substring(imps, crypto)
    if matches:
        return (
            Evidence(
                id="crypto_indicators",
                title="Cryptographic API usage",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched crypto imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no cryptographic API imports found")


def rule_shell_execution_indicators(
    features: Dict[str, Any], rule_score: float = 0.35, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    imps: Set[str] = get_imports_set(features)
    shell: Set[str] = {"winexec", "shellexecutea", "shellexecutew", "system"}
    matches = _match_imports_substring(imps, shell)
    if matches:
        return (
            Evidence(
                id="shell_exec_indicators",
                title="Shell execution capability",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="error",
                score=float(rule_score),
            ),
            f"matched shell-exec imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no shell/execution-related imports found")


def rule_autorun_persistence(
    features: Dict[str, Any], rule_score: float = 0.25, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    imps: Set[str] = get_imports_set(features)
    reg: Set[str] = {
        "regsetvaluea",
        "regsetvaluew",
        "regcreatekeya",
        "regcreatekeyw",
        "regopenkeya",
        "regopenkeyw",
    }
    matches = _match_imports_substring(imps, reg)
    if matches:
        return (
            Evidence(
                id="autorun_persistence",
                title="Potential persistence via registry",
                detail=f"Registry APIs present: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched registry imports: {', '.join(sorted(matches))}",
        )
    return None, (
        "no imports present" if not imps else "no registry persistence-related imports found"
    )


def rule_debugger_anti_debug_indicators(
    features: Dict[str, Any], rule_score: float = 0.20, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    imps: Set[str] = get_imports_set(features)
    dbg: Set[str] = {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "outputdebugstringa",
        "outputdebugstringw",
    }
    matches = _match_imports_substring(imps, dbg)
    if matches:
        return (
            Evidence(
                id="dbg_anti_dbg",
                title="Debugger/anti-debug indicators",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched debug/anti-debug imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no debugger/anti-debug imports found")


def rule_packer_artifacts(
    features: Dict[str, Any],
    rule_score: float = 0.40,
    params: Dict[str, Any] = {"no_tiny_text_factor": 0.5},
) -> Tuple[Optional[Evidence], Optional[str]]:
    """
    Packer/obfuscation hints: presence of imports like 'LoadResource', 'FindResource',
    extremely small .text, or known packer strings (UPX, MPRESS, ASPack).
    """
    imps: Set[str] = get_imports_set(features)
    strings: List[str] = [s.lower() for s in get_strings_list(features)]
    packer_tokens: Set[str] = {"upx", "mpress", "aspack", "petite", "themida"}

    hits: List[str] = []
    if any(any(tok in s for s in (strings or [])) for tok in packer_tokens):
        hits.append("packer-string")
    res_apis: Set[str] = {"loadresource", "findresource", "lockresource"}
    if _match_imports_substring(imps, res_apis):
        hits.append("resource-packaging")

    tiny_text: bool = has_tiny_text_section(features)
    if tiny_text:
        hits.append("tiny-.text")

    if not hits:
        return (
            None,
            "no packer indicators: no known packer strings, no resource-packaging APIs, and .text not tiny",
        )
    sev: str = "warn" if "tiny-.text" in hits else "info"
    score_val: float = float(rule_score)
    return (
        Evidence(
            id="packer_artifacts",
            title="Packer / obfuscation indicators",
            detail=f"Signals: {', '.join(hits)}",
            severity=sev,
            score=score_val,
        ),
        f"signals: {', '.join(hits)}",
    )


def rule_suspicious_api_combination(
    features: Dict[str, Any],
    rule_score: float = 1.00,
    params: Dict[str, Any] = {
        "inj_weight": 0.5,
        "net_weight": 0.3,
        "reg_weight": 0.2,
        "severity_error_threshold": 0.5,
    },
) -> Tuple[Optional[Evidence], Optional[str]]:
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
    if _match_imports_substring(imps, inj):
        score += params.get("inj_weight")
        hit_sets.append("process-injection")
    if _match_imports_substring(imps, net):
        score += params.get("net_weight")
        hit_sets.append("networking")
    if _match_imports_substring(imps, reg):
        score += params.get("reg_weight")
        hit_sets.append("registry")

    if score == 0.0:
        return None, "none of injection/networking/registry API sets present"
    return (
        Evidence(
            id="sus_api_combo",
            title="Suspicious API combination",
            detail=f"Hits: {', '.join(hit_sets)}",
            severity=(
                "error" if score >= float(params.get("severity_error_threshold")) else "warn"
            ),
            score=min(1.0, float(rule_score) * score),
        ),
        f"hit sets: {', '.join(hit_sets)}",
    )


def rule_tiny_text_section(
    features: Dict[str, Any],
    rule_score: float = 0.25,
    params: Dict[str, Any] = {"tiny_text_size_threshold": 4096},
) -> Tuple[Optional[Evidence], Optional[str]]:
    """
    Dedicated signal when .text section is unusually small (< 4KB).
    Even if covered in packer_artifacts, expose as its own rule for scoring flexibility.
    """
    if not has_tiny_text_section(features):
        secs: List[Dict[str, Any]] = get_nested_value(features, "sections", []) or []
        if not secs:
            return None, "no sections metadata available"
        return None, ".text section size not below threshold"
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
    thr = int(params.get("tiny_text_size_threshold"))
    detail = f"Detected tiny .text section (<{thr}B)"
    if size_info is not None and size_info > 0:
        detail += f"; size={size_info} bytes"
    return (
        Evidence(
            id="tiny_text_section",
            title="Tiny .text section",
            detail=detail,
            severity="warn",
            score=float(rule_score),
        ),
        "tiny .text section detected",
    )


def rule_low_entropy_strings(
    features: Dict[str, Any],
    rule_score: float = 0.10,
    params: Dict[str, Any] = {
        "min_prog_size": 102400,
        "low_strings_threshold": 8,
        "short_ratio_threshold": 0.8,
        "short_case_factor": 0.8,
    },
) -> Tuple[Optional[Evidence], Optional[str]]:
    """
    Very few or no human-readable strings can indicate packing or heavy obfuscation.
    We treat low string count as a proxy for "low information in strings".
    """
    strings: List[str] = get_strings_list(features)
    total: int = len(strings)
    prog_size: int = int(get_nested_value(features, "program.size", 0) or 0)
    min_prog = int(params.get("min_prog_size"))
    low_thresh = int(params.get("low_strings_threshold"))
    # Heuristic: if program is sizable but has very few strings, flag.
    if prog_size >= min_prog and total <= low_thresh:
        return (
            Evidence(
                id="low_entropy_strings",
                title="Sparse strings (possible packing)",
                detail=f"Binary size={prog_size} bytes but only {total} extracted strings",
                severity="info",
                score=float(rule_score),
            ),
            f"low string count: {total} strings for {prog_size} bytes",
        )
    # Alternatively, if there are strings but most are very short (<4 chars), also weak signal
    short = sum(1 for s in strings if len(s) < 4)
    short_ratio_thr = float(params.get("short_ratio_threshold"))
    if total > 0 and short / max(1, total) > short_ratio_thr and prog_size >= min_prog:
        return (
            Evidence(
                id="low_entropy_strings",
                title="Mostly short strings (possible packing)",
                detail=f"{short}/{total} strings <4 chars",
                severity="info",
                score=float(rule_score),
            ),
            f"short strings ratio: {short}/{total}",
        )
    # Miss reason
    if prog_size < min_prog:
        return None, "program size below threshold (<100KB) for this heuristic"
    if total == 0:
        return None, "no extracted strings"
    return None, "string count/length distribution not indicative of packing"


def rule_dynamic_api_resolution(
    features: Dict[str, Any], rule_score: float = 0.20, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    """
    LoadLibrary/GetProcAddress patterns used for late binding and API hashing.
    """
    imps: Set[str] = get_imports_set(features)
    dyn: Set[str] = {"loadlibrarya", "loadlibraryw", "getprocaddress"}
    matches = _match_imports_substring(imps, dyn)
    if matches:
        return (
            Evidence(
                id="dynamic_api_resolution",
                title="Dynamic API resolution",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched dynamic resolution imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no dynamic API resolution imports found")


def rule_service_persistence(
    features: Dict[str, Any], rule_score: float = 0.25, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
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
    matches = _match_imports_substring(imps, svc)
    if matches:
        return (
            Evidence(
                id="service_persistence",
                title="Service manipulation",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched service control imports: {', '.join(sorted(matches))}",
        )
    return None, (
        "no imports present" if not imps else "no service control manager API imports found"
    )


def rule_filesystem_modification(
    features: Dict[str, Any], rule_score: float = 0.10, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
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
    matches = _match_imports_substring(imps, fs)
    if matches:
        return (
            Evidence(
                id="filesystem_mod",
                title="Filesystem modification capability",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="info",
                score=float(rule_score),
            ),
            f"matched filesystem imports: {', '.join(sorted(matches))}",
        )
    return None, ("no imports present" if not imps else "no filesystem modification imports found")


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


def rule_suspicious_urls_in_strings(
    features: Dict[str, Any],
    rule_score: float = 0.15,
    params: Dict[str, Any] = {"warn_hits_threshold": 3, "below_threshold_ratio": 0.08},
) -> Tuple[Optional[Evidence], Optional[str]]:
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
        if not strings:
            return None, "no strings extracted"
        if urls or ips:
            return None, "only benign/social domains or invalid endpoints found"
        return None, "no URLs or IP addresses found in strings"
    # Show up to warn_hits_threshold indicators in detail
    preview = (
        filtered_urls[: int(params.get("warn_hits_threshold"))]
        + ips[: max(0, int(params.get("warn_hits_threshold")) - len(filtered_urls))]
    )
    final_score = float(
        rule_score
        * (
            1.0
            if total_hits >= int(params.get("warn_hits_threshold"))
            else float(params.get("below_threshold_ratio") / rule_score)
        )
    )
    return (
        Evidence(
            id="suspicious_urls_in_strings",
            title="Embedded external endpoints",
            detail=f"Found {total_hits} URL/IP indicators; e.g., {', '.join(preview)}",
            severity=("warn" if total_hits >= int(params.get("warn_hits_threshold")) else "info"),
            score=float(final_score),
        ),
        f"found {total_hits} endpoints",
    )


def rule_anti_vm_strings(
    features: Dict[str, Any], rule_score: float = 0.15, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
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
        if not strings:
            return None, "no strings extracted"
        return None, "no anti-VM tokens present in strings"
    return (
        Evidence(
            id="anti_vm_strings",
            title="Anti-VM indicators (strings)",
            detail=f"Tokens: {', '.join(sorted(hits))}",
            severity="warn",
            score=float(rule_score),
        ),
        f"tokens: {', '.join(sorted(hits))}",
    )


def rule_http_exfil_indicators(
    features: Dict[str, Any], rule_score: float = 0.20, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
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
    matches = _match_imports_substring(imps, http)
    if matches:
        return (
            Evidence(
                id="http_exfil_indicators",
                title="HTTP request/POST capability",
                detail=f"Imports include: {', '.join(sorted(matches))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched HTTP exfil imports: {', '.join(sorted(matches))}",
        )
    return None, (
        "no imports present" if not imps else "no HTTP request/exfiltration imports found"
    )


def rule_suspicious_function_names(
    features: Dict[str, Any], rule_score: float = 0.30, params: Dict[str, Any] = {}
) -> Tuple[Optional[Evidence], Optional[str]]:
    """
    Flags binaries containing functions with suspicious names (e.g., process injection, hooking, shellcode).
    """
    from rexis.utils.constants import SUSPICIOUS_FUNCTION_NAME_PATTERNS

    regex = re.compile("|".join(SUSPICIOUS_FUNCTION_NAME_PATTERNS), re.IGNORECASE)
    functions = features.get("functions", [])
    if not functions:
        return None, "no functions metadata available"
    hits = []
    for fn in functions:
        name = fn.get("name", "")
        if name and regex.search(name):
            hits.append(name)
    if hits:
        return (
            Evidence(
                id="suspicious_function_names",
                title="Suspicious function names detected",
                detail=f"Functions: {', '.join(sorted(hits))}",
                severity="warn",
                score=float(rule_score),
            ),
            f"matched suspicious function names: {', '.join(sorted(hits))}",
        )
    return None, "no suspicious function names found"
