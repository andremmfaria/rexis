# Reconciliation of heuristic result with VirusTotal data using a confidence-based strategy

# 1) Definition of the two signals

* **Heuristics output**: a behavior-based score `S_h ∈ [0,1]` with label (malicious/suspicious/benign) and evidence (rules fired, severities).
* **VirusTotal output**: an aggregate “maliciousness” signal `S_vt ∈ [0,1]` derived from VirusTotal stats (e.g., malicious/total engines), plus taxonomy hints (`popular_threat_name/category`), dates (first/last submission), and prevalence (names, size).

# 2) Normalization

* **Heuristics**: keep existing normalized score (already 0–1).
* **VirusTotal**: Normalize by **weighted engine consensus** (e.g., weight reputable engines higher, ignore chronically noisy vendors, cap extreme outliers). Add recency/prevalence modifiers (older/very common files slightly down-weight; brand-new rare files slightly up-weight uncertainty).

# 3) Estimate per-source confidence (with clamping)

`C_h` and `C_vt` are multipliers in \[0,1] reflecting **trust in the source for this sample**. After computation, both confidences are
clamped to configurable floors/ceilings to avoid extreme values dominating:

* `C_h = clip([C_h_floor, C_h_ceil], C_h)`
* `C_vt = clip([C_vt_floor, C_vt_ceil], C_vt)`

These limits are policy-overridable (see Policy/Overrides below) and default to constants in the reconciliation module.

**For Heuristics, `C_h` can depend on:**

* **Evidence quality**: proportion of high-severity rules (error > warn > info), diversity of independent signals (injection + persistence + networking > networking alone).
* **Coverage/fit**: did we see enough features (imports/sections/strings)? If the sample looks heavily **packed/obfuscated**, *reduce* `C_h`.
* **Historical precision** of each rule (if there is corpus validation), e.g., `CreateRemoteThread+WriteProcessMemory` had high PPV → bump `C_h`.

**For VirusTotal, `C_vt` can depend on:**

* **Consensus strength**: malicious ratio after engine weighting.
* **Engine diversity**: hits across multiple vendor “families” (not all forks of one engine).
* **Recency**: last submission freshness; very old detections get a small decay.
* **Prevalence**: extremely common clean files → bump confidence for benign; extremely rare → increase uncertainty (don’t over-trust a single hit).
* **Stability**: popular threat name/category consistent across time/vendors → higher `C_vt`.

Optional policy hooks:

* `heuristics_conf` overrides to adjust rule/feature contributions when computing `C_h`.
* `cat_map` to remap behavior categories prior to confidence/label logic.

# 4) Alignment of label taxonomies before merging

* Mapping of VT’s `popular_threat_category/name` to the **behavioral taxonomy** (ransomware, loader, banker, generic.malware, PUP).
* If VirusTotal has **only generic flags** or conflicting names, family names are treated as **hints** (low weight) but keep behavior labels driven by heuristics.

# 5) Fusing scores with confidence weighting

**Final score (pre-penalty)**

```
S_fused_pre = w_h * C_h * S_h + w_vt * C_vt * S_vt
```

* Defaults for `w_h` and `w_vt` are configured in code (policy-overridable via weights).
* Compute a **disagreement penalty** based on the absolute gap `|S_h − S_vt|` when VirusTotal data is available:
  * Penalty starts after a configurable `gap_penalty_start`, grows with slope `gap_penalty_slope`, and is capped at `gap_penalty_max`.
  * Effective fused score is clipped to [0,1]:

```
S_final = clip_01(S_fused_pre − penalty)
```

**Hard conflict override**

If both sources are high-confidence but strongly disagree, we apply a deterministic override:

* Condition: `|S_h − S_vt| ≥ conflict_gap_hard` AND `C_h ≥ high_confidence` AND `C_vt ≥ high_confidence`.
* Action: set `S_final = conflict_override_score` (a mid value) and force the label to:
  * `abstain` if `abstain_on_conflict = true` (default), otherwise `suspicious`.

This creates a conservative path when high-confidence sources disagree sharply.

Additional guidance when no hard override triggers:

* If **both high** and **agree** → keep the stronger behavior label; optionally annotate with VT names.
* If **high VirusTotal but low heuristics** → check for packer indicators; let VT contribute but expect lower overall confidence.
* If **high heuristics but low VirusTotal** → treat as **emerging/low-prevalence**; keep label, mark limited external consensus.
* If **both low** → label **benign**.
* If **mid/discordant** → label **suspicious** and recommend dynamic analysis.

# 6) Deciding the label using calibrated thresholds

Same three bands the baseline uses, but applied to `S_final`:

* `S_final ≥ T_mal` → **malicious**
* `T_susp ≤ S_final < T_mal` → **suspicious**
* `< T_susp` → **benign**

Keep thresholds adjustable (e.g., `T_mal = 0.70`, `T_susp = 0.40`) and **calibrate** them on a validation set (Platt/Isotonic if probability calibration is warranted).

# 7) Produce audit trail (current output schema)

In the final report:

The reconciler returns a structured object with the following sections:

* `schema`: version identifier (e.g., `rexis.baseline.decision.v1`).
* `inputs`:
  * `heuristics`: `{ score, label, evidence_counts: {info, warn, error} }`.
  * `virustotal`: normalized info block when available, or `{ error: vt_error | "not_available" }`.
* `confidence`: `{ heuristics_confidence, virustotal_confidence }` after clamping.
* `weights`: `{ heuristics_weight, virustotal_weight }` in effect.
* `comparison`: `{ score_gap, disagreement_penalty, conflict_override_applied }`.
* `final`: `{ score, label, thresholds: { malicious, suspicious }, decision_thresholds: { malicious, suspicious } }`.
* `explanation`: list of notes from heuristics and VirusTotal, plus entries like `disagreement_penalty=…` and whether a hard conflict override fired.

Include in the report a concise summary of VT consensus (weighted ratio, key vendors, recency, prevalence) and top heuristic evidence by severity. Document any policy choices that materially affected the outcome (e.g., packer reduced `C_h`; VT rate-limited; hard conflict override).

# 8) Handling special cases

* **No VirusTotal data or error** → set VT block to `{ error: … }`; skip disagreement penalty; rely on heuristics confidence/score.
* **Rate-limited VirusTotal** → mark enrichment as “incomplete”, don’t penalize heuristics.
* **PUP/grayware** → allow a distinct label path: moderate scores with distinct thresholds or separate mapping table.
* **Installers/updaters** often have networking/registry APIs; require **co-occurrence** of stronger signals (e.g., injection) before elevating to malicious.

# 9) Continuous calibration & QA

* Periodically **recalibrate** `w_h`, `w_vt`, thresholds, and rule weights against a labeled validation set (ROC/PR, reliability diagrams).
* Track **drift**: if VirusTotal engine policies change or the heuristics set evolves, re-tune.

---

## Examples

1) Moderate disagreement with penalty (no hard override):

* Heuristics: `S_h = 0.68`, evidence includes injection + autorun; packer present → `C_h = 0.8`.
* VirusTotal: 9/70 vendors flag; weighted consensus ~0.35; first seen 2 days ago; mixed names → `S_vt = 0.35`, `C_vt = 0.6`.
* Fusion (example weights 0.5/0.5): `S_fused_pre = 0.5*(0.8*0.68) + 0.5*(0.6*0.35) ≈ 0.377`.
* Apply small disagreement penalty (since gap=0.33 > start): `S_final ≈ 0.36`.
* With `T_susp=0.40`, `T_mal=0.70` → borderline suspicious/benign → label **suspicious** if caution is preferred, with note “low external consensus; strong injection evidence; packed—recommend sandbox run.”

2) Hard conflict override:

* Heuristics: `S_h = 0.85`, `C_h = 0.9`.
* VirusTotal: `S_vt = 0.10`, `C_vt = 0.9`.
* Gap = 0.75 ≥ `conflict_gap_hard`, both confidences high → set `S_final = conflict_override_score` and force label to `abstain` (or `suspicious` if configured). Explain the override in the audit trail.
