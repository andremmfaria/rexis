from typing import Any, Dict, Tuple

from rexis.utils.config import config

DATABASE_CONNECTION_CONNSTRING: str = (
    f"postgresql://{config.db.user}:{config.db.password}@{config.db.host}:{config.db.port}/{config.db.name}"
)

MALWAREBAZAAR_QUERY_MAX_LIMIT: int = 1000

SOCIAL_DOMAINS: Tuple[str, ...] = (
    "twitter.com",
    "x.com",
    "t.co",
    "youtube.com",
    "youtu.be",
    "facebook.com",
    "fb.com",
    "instagram.com",
    "linkedin.com",
    "lnkd.in",
    "reddit.com",
    "medium.com",
    "tiktok.com",
    "discord.com",
    "discord.gg",
    "telegram.me",
    "t.me",
)

DEFAULT_HEURISTIC_RULES: Dict[str, Any] = {
    "scoring": {
        "base": 0.0,
        "combine": "weighted_sum",  # or "max"guidesguides
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
        "tiny_text_section": 0.20,
        "entry_in_writable": 0.20,
        "low_entropy_strings": 0.10,
        "networking_indicators": 0.20,
        "http_exfil_indicators": 0.20,
        "crypto_indicators": 0.15,
        "dynamic_api_resolution": 0.15,
        "shell_exec_indicators": 0.25,
        "autorun_persistence": 0.20,
        "service_persistence": 0.20,
        "filesystem_mod": 0.10,
        "suspicious_urls_in_strings": 0.15,
        "anti_vm_strings": 0.10,
        "dbg_anti_dbg": 0.20,
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

# Centralized score thresholds for label assignment used across the codebase
# Note: "benign" here is treated as an upper-bound cutoff used when the label is
# absent or outside the allowed set; keep it conservative and configurable.
SCORE_THRESHOLD_MALICIOUS: float = float(
    DEFAULT_HEURISTIC_RULES["scoring"]["label_thresholds"].get("malicious", 0.70)
)
SCORE_THRESHOLD_SUSPICIOUS: float = float(
    DEFAULT_HEURISTIC_RULES["scoring"]["label_thresholds"].get("suspicious", 0.40)
)
SCORE_THRESHOLD_BENIGN_MAX: float = 0.20


DEFAULT_TAG_SCORES = {
    # behavioral
    "networking_indicators": {"trojan": 0.5, "backdoor": 0.5, "botnet": 0.3},
    "http_exfil_indicators": {"stealer": 0.7, "spyware": 0.6, "exfiltration": 0.8},
    "filesystem_mod": {"ransomware": 0.7, "wiper": 0.6, "dropper": 0.4},
    "shell_exec_indicators": {"dropper": 0.7, "downloader": 0.6, "loader": 0.5},
    "suspicious_urls_in_strings": {"downloader": 0.6, "trojan": 0.5},
    # persistence / evasion
    "autorun_persistence": {"persistence": 0.8, "trojan": 0.3},
    "service_persistence": {"persistence": 0.8, "backdoor": 0.4},
    "anti_vm_strings": {"evasive": 0.8},
    "dbg_anti_dbg": {"evasive": 0.7},
    # packing / obfuscation
    "packer_artifacts": {"packed": 0.9, "obfuscated": 0.6},
    "tiny_text_section": {"packed": 0.6},
    "low_entropy_strings": {"packed": 0.4},
    "entry_in_writable": {"loader": 0.5, "packed": 0.4},
    "dynamic_api_resolution": {"obfuscated": 0.7, "packed": 0.4},
    # crypto
    "crypto_indicators": {"ransomware": 0.5, "crypto_malware": 0.7},
    # generic suspicious API combo
    "sus_api_combo": {"trojan": 0.4, "backdoor": 0.3, "stealer": 0.3},
}

# Default normalization rules for vendor/threat names → canonical families
# Order matters (first match wins)
DEFAULT_NORMALIZATION_RULES = [
    (r"ransom|locker|crypt(?!o)|cryptolocker|encrypt", "ransomware"),
    (r"(bank|banload)", "banker"),
    (r"(steal|stealer|azoru?lt|redline|vidar|raccoon)", "stealer"),
    (r"agenttesla", "stealer"),
    (r"keylog", "keylogger"),
    (r"(miner|xmrig)", "miner"),
    (r"wiper", "wiper"),
    (r"worm", "worm"),
    (r"rootkit", "rootkit"),
    (r"(downloader|dldr)\b", "downloader"),
    (r"dropper", "dropper"),
    (r"loader", "loader"),
    (r"(botnet|\bbot\b)", "bot"),
    (r"adware", "adware"),
    (r"(pua|pup|riskware)", "riskware"),
    (r"(spy|spyware)", "spyware"),
    (r"backdoor|bdoor|\brat\b|remote access trojan", "backdoor"),
    (r"trojan", "trojan"),
]

# Default fused-decision settings (heuristics + VirusTotal)
DEFAULT_DECISION: Dict[str, Any] = {
    "weights": {"w_h": 0.5, "w_vt": 0.5},
    "thresholds": {"malicious": 0.70, "suspicious": 0.40},
    # Keep policy minimal here; other keys use internal defaults from ReconcileConfig
    "policy": {"gap_penalty_start": 0.35},
}


AUTH_BONUS: Dict[str, float] = {
    "malpedia": 0.05,
    "vx-underground": 0.03,
    "malwarebazaar": 0.02,
}

# Capability buckets
CAPABILITY_BUCKETS = {
    "injection": {
        "createremotethread",
        "writeprocessmemory",
        "virtualallocex",
        "ntunmapviewofsection",
        "setthreadcontext",
        "queueuserapc",
        "suspendthread",
        "resumeThread",
        "getthreadcontext",
        "createprocess",
        "createprocessasuser",
        "createprocesswithtoken",
        "setwindowshookex",
        "dllinject",
        "reflectiveinject",
        "mapviewoffile",
        "loadlibrary",
        "getprocaddress",
        "shellcode",
        "runpe",
        "processhollowing",
        "threadhijack",
    },
    "network": {
        "wsastartup",
        "connect",
        "internetopen",
        "wininet",
        "urlmon",
        "send",
        "recv",
        "socket",
        "bind",
        "listen",
        "accept",
        "gethostbyname",
        "getaddrinfo",
        "httpopenrequest",
        "internetconnect",
        "ftpgetfile",
        "ftpputfile",
        "dnsquery",
        "getifaddrs",
        "curl_easy_init",
        "libcurl",
        "websocket",
        "tcp",
        "udp",
        "icmp",
    },
    "crypto": {
        "cryptacquirecontext",
        "cryptencrypt",
        "bcrypt",
        "cryptdecrypt",
        "cryptgenrandom",
        "cryptimportkey",
        "cryptexportkey",
        "cryptderivekey",
        "crypthashdata",
        "cryptsignhash",
        "cryptverifyhash",
        "aes",
        "des",
        "rsa",
        "ecc",
        "sha256",
        "md5",
        "hmac",
        "pbkdf2",
        "openssl",
        "wincrypt",
        "hash",
        "encrypt",
        "decrypt",
    },
    "persistence": {
        "regsetvalue",
        "regcreatekey",
        "createservice",
        "schtasks",
        "setwindowshookex",
        "startup",
        "runkey",
        "taskschd",
        "serviceinstall",
        "bootexecute",
        "winlogon",
        "appinit_dlls",
        "scheduledtask",
        "autorun",
        "wmi",
        "wmipersist",
        "shortcut",
        "registry",
        "dllsearchorder",
        "imagefileexecutionoptions",
    },
    "anti_debug": {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "outputdebugstring",
        "ntqueryinformationprocess",
        "findwindow",
        "getwindowthreadprocessid",
        "debugactiveprocess",
        "debugbreak",
        "int3",
        "rdtsc",
        "gettickcount",
        "queryperformancecounter",
        "processenvironmentblock",
        "beingdebugged",
        "hide_thread",
        "unhandledexceptionfilter",
        "veh",
        "seh",
        "trapflag",
        "timingattack",
    },
    "file_ops": {
        "createfile",
        "readfile",
        "writefile",
        "deletefile",
        "copyfile",
        "movefile",
        "openfile",
        "closehandle",
        "setfileattributes",
        "getfileattributes",
        "findfirstfile",
        "findnextfile",
        "gettempfilename",
        "getfiletime",
        "setfiletime",
        "lockfile",
        "unlockfile",
    },
    "process_ops": {
        "openprocess",
        "terminateprocess",
        "getcurrentprocess",
        "getprocessid",
        "enumprocesses",
        "getprocesshandle",
        "setpriorityclass",
        "getexitcodeprocess",
        "createprocess",
        "suspendprocess",
        "resumeprocess",
        "killprocess",
    },
    "system_info": {
        "getversion",
        "getversionex",
        "getsysteminfo",
        "getnativeSystemInfo",
        "globalmemorystatusex",
        "getlogicaldrives",
        "getdrivetype",
        "getdiskfreespace",
        "getdiskfreespaceex",
        "getwindowsdirectory",
        "getsystemdirectory",
        "getenvironmentvariable",
        "getusername",
        "getcomputername",
    },
    "ui": {
        "findwindow",
        "showwindow",
        "setwindowpos",
        "getwindowrect",
        "getwindowtext",
        "sendmessage",
        "postmessage",
        "getmessage",
        "dispatchmessage",
        "setwindowshookex",
        "mouse_event",
        "keybd_event",
        "getasynckeystate",
        "getkeystate",
        "setcursorpos",
        "getcursorpos",
    },
    "compression": {
        "compress",
        "decompress",
        "zip",
        "unzip",
        "rar",
        "unrar",
        "gzip",
        "gunzip",
        "lzma",
        "bzip2",
    },
    "misc": {
        "sleep",
        "gettickcount",
        "queryperformancecounter",
        "rand",
        "srand",
        "gettimeofday",
        "time",
        "date",
        "getlocaltime",
        "setlocaltime",
        "getsystemtime",
        "setsystemtime",
    },
}
