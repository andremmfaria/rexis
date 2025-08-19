from typing import Any, Dict, Tuple

from rexis.utils.config import config

DATABASE_CONNECTION_CONNSTRING: str = (
    f"postgresql://{config.db.user}:{config.db.password}@{config.db.host}:{config.db.port}/{config.db.name}"
)

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
