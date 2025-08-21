from typing import Dict, List, Optional, TypedDict, Union
from dataclasses import dataclass


class FunctionInfo(TypedDict):
    name: str
    entry: str
    size: int
    is_thunk: bool
    calling_convention: Optional[str]


class DecompiledFunction(TypedDict, total=False):
    name: str
    entry: str
    c: str
    error: str


class ProgramInfo(TypedDict):
    name: str
    format: str
    language: str
    compiler: str
    image_base: str
    size: int
    sha256: str


class Features(TypedDict, total=False):
    program: ProgramInfo
    functions: List[FunctionInfo]
    imports: List[str]
    strings: List[str]
    decompiled: List[DecompiledFunction]
    sections: List["MemorySection"]
    libraries: List[str]
    exports: List[str]
    entry_points: List[str]


class MemorySection(TypedDict, total=False):
    name: str
    start: str
    end: str
    size: int
    initialized: bool
    read: bool
    write: bool
    execute: bool
    volatile: bool
    overlay: bool
    loaded: bool
    type: Optional[str]
    source_name: Optional[str]
    comment: Optional[str]
    # Enrichments
    entropy: float
    strings_count: int
    functions_count: int
    bytes_total: int
    bytes_sampled: int
    bytes_truncated: bool


RateLimitState = Dict[str, float]


@dataclass
class VTConfig:
    enabled: bool
    api_key: str
    qpm: int  # queries per minute (budget)


@dataclass
class Evidence:
    id: str
    title: str
    detail: str
    severity: str  # info | warn | error
    score: float = 0.0  # contribution to final score in [0,1]


@dataclass
class ReconcileConfig:
    # Fusion weights for the two signals
    heuristics_weight: float  # Weight for heuristics signal
    virustotal_weight: float  # Weight for VirusTotal signal

    # Final label thresholds on the fused score
    threshold_malicious: float  # Threshold for 'malicious' label
    threshold_suspicious: float  # Threshold for 'suspicious' label

    # Disagreement settings
    gap_penalty_start: float  # Start penalizing when |Sh - Svt| exceeds this value
    gap_penalty_max: float  # Maximum penalty cap
    gap_penalty_slope: float  # Penalty per unit gap beyond start

    # Conflict override (extreme disagreement with high confidence)
    conflict_gap_hard: float  # Hard gap threshold for conflict override
    high_confidence: float  # Confidence threshold for override
    conflict_override_score: float  # Fused score to set when hard conflict triggers


# Typed inputs for stronger type safety
class EvidenceItem(TypedDict, total=False):
    id: str
    severity: str


class HeuristicsData(TypedDict, total=False):
    score: float
    label: Optional[str]
    evidence: List[EvidenceItem]


class VirusTotalData(TypedDict, total=False):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int
    popular_threat_name: Union[str, List[str]]
    last_submission_date: int
    type_description: Optional[str]
    meaningful_name: Optional[str]
    names: List[str]
    size: int
    sha256: str


class FusionWeights(TypedDict, total=False):
    w_h: float
    w_vt: float


class Thresholds(TypedDict, total=False):
    malicious: float
    suspicious: float


class ReconcilePolicyOverrides(TypedDict, total=False):
    gap_penalty_start: float
    gap_penalty_max: float
    gap_penalty_slope: float
    conflict_gap_hard: float
    high_conf: float
    conflict_override_score: float


class RagNotes(TypedDict, total=False):
    query_count: int
    top_k_dense: int
    top_k_keyword: int
    join_mode: str
    rerank_top_k: int
    final_top_k: int
    filters: Dict[str, Union[str, List[str], Dict[str, Union[str, List[str]]]]]
    ranker_model: str
    embedding_model: str
    metric: str
    dense_hits: int
    keyword_hits: int
    fused_unique: int
    elapsed_ms: int
    error: str
    note: str


class Passage(TypedDict, total=False):
    doc_id: str
    source: Optional[str]
    title: Optional[str]
    score: Optional[float]
    text: str
