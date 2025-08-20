from typing import List, Optional, TypedDict, Union
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


class ReconcileConfig:
    # fusion weights for the two signals
    w_h: float = 0.5  # heuristics weight
    w_vt: float = 0.5  # VirusTotal weight

    # final label thresholds on the fused score
    t_malicious: float = 0.70
    t_suspicious: float = 0.40

    # disagreement settings
    gap_penalty_start: float = 0.35  # start penalizing when |Sh - Svt| exceeds this
    gap_penalty_max: float = 0.10  # cap penalty
    gap_penalty_slope: float = 0.20  # penalty per unit gap beyond start

    # conflict override (extreme disagreement with high confidence)
    conflict_gap_hard: float = 0.50
    high_conf: float = 0.70
    conflict_override_score: float = 0.50  # set fused score to this when hard conflict triggers


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
