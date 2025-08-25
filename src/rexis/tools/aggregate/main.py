import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rexis.tools.aggregate.parsers import parse_baseline, parse_llmrag
from rexis.tools.aggregate.utils import load_json, scan_reports, truth_category_from_path, wilson_ci
from rexis.tools.aggregate.vt_helpers import vt_all_categories, vt_truth_category
from rexis.utils.utils import safe_get


@dataclass
class AggregateArgs:
    baseline_dirs: List[str]
    baseline_vt_dirs: List[str]
    llmrag_dirs: List[str]
    out_dir: Path
    debug: bool = False
    alpha: float = 1.0 / 3.0  # accuracy weight
    beta: float = 1.0 / 3.0  # efficiency weight (applied to inverse)
    gamma: float = 1.0 / 3.0  # interpretability weight


def parse_baseline_vt(report: Dict[str, Any], debug: bool = False) -> Dict[str, Any]:
    row = parse_baseline(report)
    truth_category, truth_info = vt_truth_category(report)
    row.update(
        {
            "truth_category": truth_category,
            "truth_info": truth_info,
            "vt_malicious": safe_get(report, ["virus_total", "data", "malicious"]),
            "vt_total": safe_get(report, ["virus_total", "data", "total"])
            or safe_get(report, ["virus_total", "data", "scanned"]),
            "vt_categories": vt_all_categories(report),
        }
    )
    if debug and (not truth_category):
        sha = row.get("sha256")
        print(
            f"[truth-miss] sha={sha} vendor_str_count={truth_info.get('vendor_str_count')} method={truth_info.get('method')}"
        )
    return row


def aggregate(args: AggregateArgs) -> Dict[str, Any]:
    baseline_rows: List[Dict[str, Any]] = []
    baseline_vt_rows: List[Dict[str, Any]] = []
    llmrag_rows: List[Dict[str, Any]] = []

    for report_path in scan_reports(args.baseline_dirs):
        report = load_json(report_path)
        if report and str(safe_get(report, ["schema"], "")).startswith("rexis.baseline.report"):
            row = parse_baseline(report)
            row["which"] = "baseline"
            baseline_rows.append(row)

    for report_path in scan_reports(args.baseline_vt_dirs):
        report = load_json(report_path)
        if report and str(safe_get(report, ["schema"], "")).startswith("rexis.baseline.report"):
            row = parse_baseline_vt(report, debug=args.debug)
            # Override VT-derived truth with directory-derived truth if available
            dir_category = truth_category_from_path(report_path)
            if dir_category:
                row["truth_category"] = dir_category
                row["truth_info"] = {"method": "dir_name"}
            row["which"] = "baseline_vt"
            baseline_vt_rows.append(row)

    for report_path in scan_reports(args.llmrag_dirs):
        report = load_json(report_path)
        if report and str(safe_get(report, ["schema"], "")).startswith("rexis.llmrag.report"):
            row = parse_llmrag(report)
            row["which"] = "llmrag"
            llmrag_rows.append(row)

    results_by_sha: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for row in baseline_rows + baseline_vt_rows + llmrag_rows:
        sha = row.get("sha256")
        if not sha:
            continue
        results_by_sha[sha][row["which"]] = row
        results_by_sha[sha]["sha256"] = sha

    fieldnames = [
        "sha256",
        "truth_category",
        "vt_malicious",
        "vt_total",
        "vt_categories",
        "baseline_label",
        "baseline_pred_categories",
        "baseline_duration_sec",
        "baseline_vt_label",
        "baseline_vt_pred_categories",
        "baseline_vt_duration_sec",
        "llmrag_label",
        "llmrag_pred_categories",
        "llmrag_duration_sec",
        "explanation_present_baseline",
        "explanation_present_llmrag",
        "grounding_ge1_llmrag",
        "grounding_ge2_llmrag",
        # Optional: rule-match counts for baseline variants (useful for audits)
        "rules_triggered_baseline",
        "rules_consistent_baseline",
        "rules_triggered_baseline_vt",
        "rules_consistent_baseline_vt",
    ]

    # Ensure output directory exists and define report paths
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_csv_path = args.out_dir / "aggregation-report.csv"
    with open(out_csv_path, "w", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        csv_writer.writeheader()
        for sha, sample_group in sorted(results_by_sha.items()):
            baseline_vt_entry = sample_group.get("baseline_vt", {})
            csv_writer.writerow(
                {
                    "sha256": sha,
                    "truth_category": baseline_vt_entry.get("truth_category"),
                    "vt_malicious": baseline_vt_entry.get("vt_malicious"),
                    "vt_total": baseline_vt_entry.get("vt_total"),
                    "vt_categories": ",".join(baseline_vt_entry.get("vt_categories") or []),
                    "baseline_label": safe_get(sample_group, ["baseline", "label"]),
                    "baseline_pred_categories": ",".join(
                        safe_get(sample_group, ["baseline", "pred_categories"]) or []
                    ),
                    "baseline_duration_sec": safe_get(sample_group, ["baseline", "duration_sec"]),
                    "baseline_vt_label": safe_get(sample_group, ["baseline_vt", "label"]),
                    "baseline_vt_pred_categories": ",".join(
                        safe_get(sample_group, ["baseline_vt", "pred_categories"]) or []
                    ),
                    "baseline_vt_duration_sec": safe_get(
                        sample_group, ["baseline_vt", "duration_sec"]
                    ),
                    "llmrag_label": safe_get(sample_group, ["llmrag", "label"]),
                    "llmrag_pred_categories": ",".join(
                        safe_get(sample_group, ["llmrag", "pred_categories"]) or []
                    ),
                    "llmrag_duration_sec": safe_get(sample_group, ["llmrag", "duration_sec"]),
                    "explanation_present_baseline": safe_get(
                        sample_group, ["baseline", "explanation_present"]
                    ),
                    "explanation_present_llmrag": safe_get(
                        sample_group, ["llmrag", "explanation_present"]
                    ),
                    "grounding_ge1_llmrag": safe_get(sample_group, ["llmrag", "grounding_ge1"]),
                    "grounding_ge2_llmrag": safe_get(sample_group, ["llmrag", "grounding_ge2"]),
                    "rules_triggered_baseline": safe_get(
                        sample_group, ["baseline", "rules_triggered"]
                    ),
                    "rules_consistent_baseline": safe_get(
                        sample_group, ["baseline", "rules_consistent"]
                    ),
                    "rules_triggered_baseline_vt": safe_get(
                        sample_group, ["baseline_vt", "rules_triggered"]
                    ),
                    "rules_consistent_baseline_vt": safe_get(
                        sample_group, ["baseline_vt", "rules_consistent"]
                    ),
                }
            )

    def compute_accuracy_counts(which_pipeline: str) -> Tuple[int, int]:
        correct_count = total_count = 0
        for sample_group in results_by_sha.values():
            # Ground truth: strictly the directory-derived category (already populated
            # into baseline_vt.truth_category earlier). VT categories are informational only.
            truth_category = safe_get(sample_group, ["baseline_vt", "truth_category"])
            predicted_categories = safe_get(sample_group, [which_pipeline, "pred_categories"]) or []
            # Build a comparable list: include single top category plus any list we collected
            pred_set = set()
            if isinstance(predicted_categories, list):
                pred_set = {str(x).lower() for x in predicted_categories if x}
            truth_set = {str(truth_category).lower()} if truth_category else set()
            if not truth_set or not pred_set:
                continue
            total_count += 1
            if pred_set.intersection(truth_set):
                correct_count += 1
        return correct_count, total_count

    baseline_correct, baseline_total = compute_accuracy_counts("baseline")
    baseline_vt_correct, baseline_vt_total = compute_accuracy_counts("baseline_vt")
    llmrag_correct, llmrag_total = compute_accuracy_counts("llmrag")
    baseline_ci = wilson_ci(baseline_correct, baseline_total)
    baseline_vt_ci = wilson_ci(baseline_vt_correct, baseline_vt_total)
    llmrag_ci = wilson_ci(llmrag_correct, llmrag_total)

    # Pipeline-specific denominators (samples that have results for the pipeline)
    baseline_count = sum(
        1 for sample_group in results_by_sha.values() if "baseline" in sample_group
    )
    baseline_vt_count = sum(
        1 for sample_group in results_by_sha.values() if "baseline_vt" in sample_group
    )
    llmrag_count = sum(1 for sample_group in results_by_sha.values() if "llmrag" in sample_group)

    baseline_mean_latency = sum(
        float(safe_get(sample_group, ["baseline", "duration_sec"]) or 0.0)
        for sample_group in results_by_sha.values()
    ) / max(1, baseline_count)
    baseline_vt_mean_latency = sum(
        float(safe_get(sample_group, ["baseline_vt", "duration_sec"]) or 0.0)
        for sample_group in results_by_sha.values()
    ) / max(1, baseline_vt_count)
    llmrag_mean_latency = sum(
        float(safe_get(sample_group, ["llmrag", "duration_sec"]) or 0.0)
        for sample_group in results_by_sha.values()
    ) / max(1, llmrag_count)

    total_samples = len(results_by_sha)
    # Coverage and grounding counts
    baseline_evidence_count = sum(
        1
        for sample_group in results_by_sha.values()
        if safe_get(sample_group, ["baseline", "explanation_present"])
    )
    baseline_vt_evidence_count = sum(
        1
        for sample_group in results_by_sha.values()
        if safe_get(sample_group, ["baseline_vt", "explanation_present"])
    )
    llmrag_evidence_count = sum(
        1
        for sample_group in results_by_sha.values()
        if safe_get(sample_group, ["llmrag", "explanation_present"])
    )
    llmrag_grounding_ge1_count = sum(
        1
        for sample_group in results_by_sha.values()
        if safe_get(sample_group, ["llmrag", "explanation_present"])
        and safe_get(sample_group, ["llmrag", "grounding_ge1"])
    )
    llmrag_grounding_ge2_count = sum(
        1
        for sample_group in results_by_sha.values()
        if safe_get(sample_group, ["llmrag", "explanation_present"])
        and safe_get(sample_group, ["llmrag", "grounding_ge2"])
    )
    # Rule-match counts (baseline variants)
    baseline_rules_triggered = sum(
        int(safe_get(sample_group, ["baseline", "rules_triggered"]) or 0)
        for sample_group in results_by_sha.values()
    )
    baseline_rules_consistent = sum(
        int(safe_get(sample_group, ["baseline", "rules_consistent"]) or 0)
        for sample_group in results_by_sha.values()
    )
    baseline_vt_rules_triggered = sum(
        int(safe_get(sample_group, ["baseline_vt", "rules_triggered"]) or 0)
        for sample_group in results_by_sha.values()
    )
    baseline_vt_rules_consistent = sum(
        int(safe_get(sample_group, ["baseline_vt", "rules_consistent"]) or 0)
        for sample_group in results_by_sha.values()
    )
    llmrag_abstentions_count = sum(
        1
        for sample_group in results_by_sha.values()
        if (str(safe_get(sample_group, ["llmrag", "label"]) or "").lower() == "unknown")
    )

    # Ratios per spec
    baseline_accuracy = (baseline_correct / baseline_total) if baseline_total else 0.0
    baseline_vt_accuracy = (baseline_vt_correct / baseline_vt_total) if baseline_vt_total else 0.0
    llmrag_accuracy = (llmrag_correct / llmrag_total) if llmrag_total else 0.0

    baseline_coverage_ratio = (baseline_evidence_count / baseline_count) if baseline_count else 0.0
    baseline_vt_coverage_ratio = (
        (baseline_vt_evidence_count / baseline_vt_count) if baseline_vt_count else 0.0
    )
    llmrag_coverage_ratio = (llmrag_evidence_count / llmrag_count) if llmrag_count else 0.0
    llmrag_grounding_ratio = (
        (llmrag_grounding_ge1_count / llmrag_evidence_count) if llmrag_evidence_count else 0.0
    )
    baseline_rulematch_ratio = (
        (baseline_rules_consistent / baseline_rules_triggered) if baseline_rules_triggered else 0.0
    )
    baseline_vt_rulematch_ratio = (
        (baseline_vt_rules_consistent / baseline_vt_rules_triggered)
        if baseline_vt_rules_triggered
        else 0.0
    )

    # Efficiency inverse score in [0,1): 1/(1+mean_latency)
    baseline_efficiency_score = 1.0 / (1.0 + max(0.0, float(baseline_mean_latency)))
    baseline_vt_efficiency_score = 1.0 / (1.0 + max(0.0, float(baseline_vt_mean_latency)))
    llmrag_efficiency_score = 1.0 / (1.0 + max(0.0, float(llmrag_mean_latency)))

    # Interpretability scores (average of available sub-metrics)
    baseline_interpretability_score = (
        (baseline_coverage_ratio + baseline_rulematch_ratio) / 2.0 if baseline_count else 0.0
    )
    baseline_vt_interpretability_score = (
        (baseline_vt_coverage_ratio + baseline_vt_rulematch_ratio) / 2.0
        if baseline_vt_count
        else 0.0
    )
    llmrag_interpretability_score = (
        (llmrag_coverage_ratio + llmrag_grounding_ratio) / 2.0 if llmrag_count else 0.0
    )

    # Composite scores per pipeline
    weight_alpha, weight_beta, weight_gamma = args.alpha, args.beta, args.gamma
    baseline_composite_score = (
        weight_alpha * baseline_accuracy
        + weight_beta * baseline_efficiency_score
        + weight_gamma * baseline_interpretability_score
    )
    baseline_vt_composite_score = (
        weight_alpha * baseline_vt_accuracy
        + weight_beta * baseline_vt_efficiency_score
        + weight_gamma * baseline_vt_interpretability_score
    )
    llmrag_composite_score = (
        weight_alpha * llmrag_accuracy
        + weight_beta * llmrag_efficiency_score
        + weight_gamma * llmrag_interpretability_score
    )

    summary: Dict[str, Any] = {
        "total_samples_joined": total_samples,
        "prediction_accuracy": {
            "baseline": {
                "correct": baseline_correct,
                "total_evaluated": baseline_total,
                "wilson_ci_95": baseline_ci,
            },
            "baseline_vt": {
                "correct": baseline_vt_correct,
                "total_evaluated": baseline_vt_total,
                "wilson_ci_95": baseline_vt_ci,
            },
            "llmrag": {
                "correct": llmrag_correct,
                "total_evaluated": llmrag_total,
                "wilson_ci_95": llmrag_ci,
            },
        },
        "mean_inference_latency_seconds": {
            "baseline": baseline_mean_latency,
            "baseline_vt": baseline_vt_mean_latency,
            "llmrag": llmrag_mean_latency,
        },
        "interpretability_metrics": {
            # Raw counts
            "baseline_explanations_present_count": baseline_evidence_count,
            "baseline_vt_explanations_present_count": baseline_vt_evidence_count,
            "llmrag_explanations_present_count": llmrag_evidence_count,
            "llmrag_grounding_at_least_one_reference_count": llmrag_grounding_ge1_count,
            "llmrag_grounding_at_least_two_references_count": llmrag_grounding_ge2_count,
            "llmrag_abstentions_count": llmrag_abstentions_count,
            "baseline_rules_triggered_count": baseline_rules_triggered,
            "baseline_rules_consistent_count": baseline_rules_consistent,
            "baseline_vt_rules_triggered_count": baseline_vt_rules_triggered,
            "baseline_vt_rules_consistent_count": baseline_vt_rules_consistent,
            # Ratios
            "explanation_coverage_ratio": {
                "baseline": baseline_coverage_ratio,
                "baseline_vt": baseline_vt_coverage_ratio,
                "llmrag": llmrag_coverage_ratio,
            },
            "llmrag_grounding_ratio": llmrag_grounding_ratio,
            "rule_match_consistency_ratio": {
                "baseline": baseline_rulematch_ratio,
                "baseline_vt": baseline_vt_rulematch_ratio,
            },
        },
        "composite_and_component_scores": {
            "weighting_coefficients": {
                "alpha_accuracy_weight": weight_alpha,
                "beta_efficiency_weight": weight_beta,
                "gamma_interpretability_weight": weight_gamma,
            },
            "baseline": {
                "accuracy_score": baseline_accuracy,
                "efficiency_score": baseline_efficiency_score,
                "interpretability_score": baseline_interpretability_score,
                "composite_score": baseline_composite_score,
            },
            "baseline_vt": {
                "accuracy_score": baseline_vt_accuracy,
                "efficiency_score": baseline_vt_efficiency_score,
                "interpretability_score": baseline_vt_interpretability_score,
                "composite_score": baseline_vt_composite_score,
            },
            "llmrag": {
                "accuracy_score": llmrag_accuracy,
                "efficiency_score": llmrag_efficiency_score,
                "interpretability_score": llmrag_interpretability_score,
                "composite_score": llmrag_composite_score,
            },
        },
        "output_csv_path": str(out_csv_path),
    }

    # Also persist a JSON with all metrics in the same directory
    out_json_path = args.out_dir / "aggregation-output.json"
    try:
        with open(out_json_path, "w", encoding="utf-8") as jf:
            json.dump(summary, jf, indent=2)
        summary["output_json_path"] = str(out_json_path)
    except Exception as e:
        # Surface minimal info without crashing aggregation
        summary["output_json_error"] = str(e)

    return summary
