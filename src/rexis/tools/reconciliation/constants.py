from typing import Dict

# Mapping from heuristic rule IDs to broader categories for diversity/confidence calc
CAT_MAP: Dict[str, str] = {
    "sus_api_combo": "inj",
    "shell_exec_indicators": "inj",
    "entry_in_writable": "memsec",
    "networking_indicators": "net",
    "http_exfil_indicators": "net",
    "suspicious_urls_in_strings": "net",
    "crypto_indicators": "crypto",
    "autorun_persistence": "persist",
    "service_persistence": "persist",
    "dbg_anti_dbg": "anti",
    "anti_vm_strings": "anti",
    "packer_artifacts": "obf",
    "tiny_text_section": "obf",
    "low_entropy_strings": "obf",
    "dynamic_api_resolution": "obf",
    "filesystem_mod": "fs",
}


# Simple string label constants (avoid Enums to keep JSON serialization straightforward)
LABEL_MALICIOUS: str = "malicious"
LABEL_SUSPICIOUS: str = "suspicious"
LABEL_BENIGN: str = "benign"
LABEL_ABSTAIN: str = "abstain"


# Heuristics confidence tuning defaults
HEUR_BASE: float = 0.60
HEUR_ERROR_BOOST: float = 0.20
HEUR_WARN_BOOST: float = 0.10
DIVERSITY_BONUS_3: float = 0.10  # categories >= 3
DIVERSITY_BONUS_2: float = 0.05  # categories >= 2
PACKER_ONLY_PENALTY: float = 0.15
NO_EVIDENCE_PENALTY: float = 0.25

# Confidence clamp defaults
CH_FLOOR: float = 0.20
CH_CEIL: float = 0.95
CVT_FLOOR: float = 0.20
CVT_CEIL: float = 0.95

# VirusTotal fusion tuning defaults
VT_SUSP_WEIGHT: float = 0.5
VT_LOW_COVERAGE_DENOM_THRESHOLD: int = 5
VT_BASE_LOW_COVERAGE: float = 0.45
VT_BASE_DEFAULT: float = 0.60
VT_MAL_GE_BONUS_COUNT: int = 5
VT_MAL_GE_BONUS: float = 0.10
VT_DENOM_GE_BONUS_COUNT: int = 20
VT_DENOM_GE_BONUS: float = 0.10
VT_LOW_MAL_MAX: int = 1
VT_LOW_MAL_LOW_SCORE: float = 0.20
VT_LOW_MAL_PENALTY: float = 0.10
VT_THREAT_NAME_BONUS: float = 0.05
VT_RECENT_DAYS_THRESHOLD: int = 90
VT_RECENT_BONUS: float = 0.05
VT_OLD_DAYS_THRESHOLD: int = 730
VT_OLD_PENALTY: float = 0.05

# Centralized defaults used by ReconcileConfig (fusion behavior)
DECISION_CONFIG_DEFAULTS: Dict[str, float] = {
    # Fusion weights for the two signals
    "heuristics_weight": 0.5,  # Weight for heuristics signal
    "virustotal_weight": 0.5,  # Weight for VirusTotal signal
    # Final label thresholds on the fused score
    "threshold_malicious": 0.70,  # Threshold for 'malicious' label
    "threshold_suspicious": 0.40,  # Threshold for 'suspicious' label
    # Disagreement settings
    "gap_penalty_start": 0.35,  # Start penalizing when |Sh - Svt| exceeds this value
    "gap_penalty_max": 0.10,  # Maximum penalty cap
    "gap_penalty_slope": 0.20,  # Penalty per unit gap beyond start
    # Conflict override (extreme disagreement with high confidence)
    "conflict_gap_hard": 0.50,  # Hard gap threshold for conflict override
    "high_confidence": 0.70,  # Confidence threshold for override
    "conflict_override_score": 0.50,  # Fused score to set when hard conflict triggers
}
