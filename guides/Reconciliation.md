# Reconciliation of heuristic result with VirusTotal data using a confidence-based strategy

# 1) Definition of the two signals

* **Heuristics output**: a behavior-based score `S_h ∈ [0,1]` with label (malicious/suspicious/benign) and evidence (rules fired, severities).
* **VirusTotal output**: an aggregate “maliciousness” signal `S_vt ∈ [0,1]` derived from VirusTotal stats (e.g., malicious/total engines), plus taxonomy hints (`popular_threat_name/category`), dates (first/last submission), and prevalence (names, size).

# 2) Normalization

* **Heuristics**: keep existing normalized score (already 0–1).
* **VirusTotal**: Normalize by **weighted engine consensus** (e.g., weight reputable engines higher, ignore chronically noisy vendors, cap extreme outliers). Add recency/prevalence modifiers (older/very common files slightly down-weight; brand-new rare files slightly up-weight uncertainty).

# 3) Estimate per-source confidence

`C_h` and `C_vt` as multipliers in \[0,1] reflecting **trust in the source for this sample**.

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

# 4) Alignment of label taxonomies before merging

* Mapping of VT’s `popular_threat_category/name` to the **behavioral taxonomy** (ransomware, loader, banker, generic.malware, PUP).
* If VirusTotal has **only generic flags** or conflicting names, family names are treated as **hints** (low weight) but keep behavior labels driven by heuristics.

# 5) Fusing scores with confidence weighting

**Final score**

```
S_final = w_h * C_h * S_h + w_vt * C_vt * S_vt
```

* Starts with `w_h = w_vt = 0.5`. (Possibility needs tunning)
* Add a **disagreement penalty** optionally if the two sources are far apart:

  * If `|S_h − S_vt| > δ`, subtract a small penalty proportional to the gap (encourages abstention/“suspicious” when sources conflict strongly).

**Conflict resolution add-ons**

* If **both high** and **agree** → boost confidence and keep the stronger behavior label; VirusTotal name can annotate the report (e.g., “likely AgentTesla (low confidence name)”).
* If **high VirusTotal but low heuristics** → check for obfuscation/packer evidence; if present, allow VirusTotal to dominate but **lower overall confidence** (packed loaders may fool rules).
* If **high heuristics but low VirusTotal** → treat as **likely new/low-prevalence** sample; keep label but mark “limited external consensus”.
* If **both low** → label **benign**.
* If **mid/discordant** → label **suspicious** and recommend dynamic analysis or sandboxing.

# 6) Deciding the label using calibrated thresholds

Same three bands the baseline uses, but applied to `S_final`:

* `S_final ≥ T_mal` → **malicious**
* `T_susp ≤ S_final < T_mal` → **suspicious**
* `< T_susp` → **benign**

Keep thresholds adjustable (e.g., `T_mal = 0.70`, `T_susp = 0.40`) and **calibrate** them on a validation set (Platt/Isotonic if probability calibration is warranted).

# 7) Produce audit trail

In the final report:

* Show `S_h`, `C_h`, `S_vt`, `C_vt`, weights, the disagreement penalty (if applied), and `S_final`.
* List top heuristic evidence (rule → severity → contribution).
* Summarize VirusTotal: malicious/total, weighted consensus, key vendors that flagged it, recency, prevalence, and any `popular_threat_name` (marked with **confidence level**).
* Record **why** one source dominated (e.g., “packer indicators reduced heuristic confidence” or “low VirusTotal consensus; treated as emerging sample”).

# 8) Handling special cases

* **No VirusTotal record** → `C_vt = 0`, rely on heuristics; still report “VT: not found”.
* **Rate-limited VirusTotal** → mark enrichment as “incomplete”, don’t penalize heuristics.
* **PUP/grayware** → allow a distinct label path: moderate scores with distinct thresholds or separate mapping table.
* **Installers/updaters** often have networking/registry APIs; require **co-occurrence** of stronger signals (e.g., injection) before elevating to malicious.

# 9) Continuous calibration & QA

* Periodically **recalibrate** `w_h`, `w_vt`, thresholds, and rule weights against a labeled validation set (ROC/PR, reliability diagrams).
* Track **drift**: if VirusTotal engine policies change or the heuristics set evolves, re-tune.

---

## Example

* Heuristics: `S_h = 0.68`, evidence includes injection + autorun; packer present → `C_h = 0.8`.
* VirusTotal: 9/70 vendors flag; weighted consensus \~0.35; first seen 2 days ago; mixed names → `S_vt = 0.35`, `C_vt = 0.6`.
* Fusion (equal weights): `S_final = 0.5*(0.8*0.68) + 0.5*(0.6*0.35) ≈ 0.272 + 0.105 = 0.377`.
* Apply small disagreement penalty (because 0.68 vs 0.35): `S_final ≈ 0.36`.
* With `T_susp=0.40`, `T_mal=0.70` → **borderline suspicious/benign**.
  If caution is warranted, label **suspicious**, include “low external consensus; strong injection evidence; packed—recommend sandbox run.”
