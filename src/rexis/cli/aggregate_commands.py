from pathlib import Path

import typer
from rexis.tools.aggregate.main import AggregateArgs, aggregate


def aggregate_cmd(
    baseline_dir: list[str] = typer.Option(
        ..., "--baseline-dir", help="Glob(s) for baseline runs (no VT)", show_default=False
    ),
    baseline_vt_dir: list[str] = typer.Option(
        ...,
        "--baseline-vt-dir",
        help="Glob(s) for baseline+VT runs (ground truth comes from directory label)",
        show_default=False,
    ),
    llmrag_dir: list[str] = typer.Option(
        ..., "--llmrag-dir", help="Glob(s) for LLM+RAG runs", show_default=False
    ),
    out_dir: Path = typer.Option(
        Path.cwd(), "--out-dir", help="Output directory for aggregation artifacts"
    ),
    debug: bool = typer.Option(False, "--debug", help="Verbose debug output for VT truth misses"),
    alpha: float | None = typer.Option(
        None,
        "--alpha",
        help="Composite weight for Accuracy (defaults to 1/3; if any of alpha/beta/gamma set, weights are normalized)",
    ),
    beta: float | None = typer.Option(
        None,
        "--beta",
        help="Composite weight for Efficiency^{-1} (defaults to 1/3; if any set, weights are normalized)",
    ),
    gamma: float | None = typer.Option(
        None,
        "--gamma",
        help="Composite weight for Interpretability (defaults to 1/3; if any set, weights are normalized)",
    ),
):
    """Aggregate evaluation metrics across runs and write a CSV.

    Example:
      rexis aggregate --baseline-dir analysis/baseline/baseline-analysis-*-run-* \
                      --baseline-vt-dir analysis/baseline/baseline-analysis-*-run-vt-* \
                      --llmrag-dir analysis/llmrag/llmrag-analysis-*-run-* \
                      --out-dir analysis/aggregate

    Note
    ----
    This aggregation command was created specifically to support the author’s experiments.
    Ground truth is derived from the analysis directory label (e.g., "baseline-analysis-rootkit-…").
    If a run directory does not follow this pattern or the label isn’t a known category,
    the tool falls back to VirusTotal-derived truth. All VT-derived categories are captured
    in the CSV as `vt_categories` for reference.

    Reference commands used to generate those experiments:

    Baseline with VirusTotal enrichment (per tag):

    pdm run rexis analyse baseline --input ./samples/botnet/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name botnet-run-vt-2508 --vt --overwrite
    pdm run rexis analyse baseline --input ./samples/ransomware/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name ransomware-run-vt-2508 --vt --overwrite
    pdm run rexis analyse baseline --input ./samples/rootkit/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name rootkit-run-vt-2508 --vt --overwrite
    pdm run rexis analyse baseline --input ./samples/trojan/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name trojan-run-vt-2508 --vt --overwrite

    Baseline without VirusTotal enrichment (per tag):

    pdm run rexis analyse baseline --input ./samples/botnet/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name botnet-run-2508 --overwrite
    pdm run rexis analyse baseline --input ./samples/ransomware/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name ransomware-run-2508 --overwrite
    pdm run rexis analyse baseline --input ./samples/rootkit/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name rootkit-run-2508 --overwrite
    pdm run rexis analyse baseline --input ./samples/trojan/decompressed \
        --out-dir ./analysis/baseline --parallel 5 \
        --run-name trojan-run-2508 --overwrite

    LLM+RAG pipeline:

    pdm run rexis analyse llmrag --input ./samples/botnet/decompressed \
        --out-dir ./analysis/llmrag --parallel 5 \
        --run-name botnet-run-llmrag-2508 --overwrite \
        --top-k-dense 50 --top-k-keyword 50 --final-top-k 8 --join rrf \
        --model gpt-4o-2024-08-06 --temperature 0 --max-tokens 1024

    pdm run rexis analyse llmrag --input ./samples/ransomware/decompressed \
        --out-dir ./analysis/llmrag --parallel 5 \
        --run-name ransomware-run-llmrag-2508 --overwrite \
        --top-k-dense 50 --top-k-keyword 50 --final-top-k 8 --join rrf \
        --model gpt-4o-2024-08-06 --temperature 0 --max-tokens 1024

    pdm run rexis analyse llmrag --input ./samples/rootkit/decompressed \
        --out-dir ./analysis/llmrag --parallel 5 \
        --run-name rootkit-run-llmrag-2508 --overwrite \
        --top-k-dense 50 --top-k-keyword 50 --final-top-k 8 --join rrf \
        --model gpt-4o-2024-08-06 --temperature 0 --max-tokens 1024

    pdm run rexis analyse llmrag --input ./samples/trojan/decompressed \
        --out-dir ./analysis/llmrag --parallel 5 \
        --run-name trojan-run-llmrag-2508 --overwrite \
        --top-k-dense 50 --top-k-keyword 50 --final-top-k 8 --join rrf \
        --model gpt-4o-2024-08-06 --temperature 0 --max-tokens 1024
    """
    # Normalize weights if any provided
    if any(v is not None for v in (alpha, beta, gamma)):
        a = float(alpha or 0.0)
        b = float(beta or 0.0)
        g = float(gamma or 0.0)
        s = a + b + g
        if s <= 0:
            # fallback to defaults
            a = b = g = 1.0 / 3.0
        else:
            a, b, g = a / s, b / s, g / s
    else:
        a = b = g = 1.0 / 3.0

    args = AggregateArgs(
        baseline_dirs=list(baseline_dir),
        baseline_vt_dirs=list(baseline_vt_dir),
        llmrag_dirs=list(llmrag_dir),
        out_dir=out_dir,
        debug=debug,
        alpha=a,
        beta=b,
        gamma=g,
    )
    summary = aggregate(args)

    # Compact summary printing
    def pct(k: int, n: int) -> float:
        return (100.0 * k / n) if n else 0.0

    k_b = summary["prediction_accuracy"]["baseline"]["correct"]
    n_b = summary["prediction_accuracy"]["baseline"]["total_evaluated"]
    k_v = summary["prediction_accuracy"]["baseline_vt"]["correct"]
    n_v = summary["prediction_accuracy"]["baseline_vt"]["total_evaluated"]
    k_r = summary["prediction_accuracy"]["llmrag"]["correct"]
    n_r = summary["prediction_accuracy"]["llmrag"]["total_evaluated"]
    c_b = summary["prediction_accuracy"]["baseline"]["wilson_ci_95"]
    c_v = summary["prediction_accuracy"]["baseline_vt"]["wilson_ci_95"]
    c_r = summary["prediction_accuracy"]["llmrag"]["wilson_ci_95"]

    typer.echo("=== REXIS Evaluation Summary (category accuracy) ===")
    typer.echo(f"Samples (joined by sha256): {summary['total_samples_joined']}")
    typer.echo("-- Accuracy (category; skipping 'unknown' predictions) --")
    typer.echo(
        f"Baseline:     {k_b}/{n_b} = {pct(k_b, n_b):.1f}%  (Wilson 95% CI: {100*c_b[0]:.1f}–{100*c_b[1]:.1f}%)"
    )
    typer.echo(
        f"Baseline+VT:  {k_v}/{n_v} = {pct(k_v, n_v):.1f}%  (Wilson 95% CI: {100*c_v[0]:.1f}–{100*c_v[1]:.1f}%)"
    )
    typer.echo(
        f"LLM+RAG:      {k_r}/{n_r} = {pct(k_r, n_r):.1f}%  (Wilson 95% CI: {100*c_r[0]:.1f}–{100*c_r[1]:.1f}%)"
    )
    typer.echo("-- Latency (mean duration_sec) --")
    typer.echo(
        f"Baseline:     {summary['mean_inference_latency_seconds']['baseline']:.3f}s\n"
        f"Baseline+VT:  {summary['mean_inference_latency_seconds']['baseline_vt']:.3f}s\n"
        f"LLM+RAG:      {summary['mean_inference_latency_seconds']['llmrag']:.3f}s"
    )
    typer.echo("-- Interpretability --")
    typer.echo(
        f"Coverage (baseline evidence present): {summary['interpretability_metrics']['baseline_explanations_present_count']}/{summary['total_samples_joined']}"
    )
    typer.echo(
        f"Coverage ratio: baseline={summary['interpretability_metrics']['explanation_coverage_ratio']['baseline']:.3f}, "
        f"baseline+VT={summary['interpretability_metrics']['explanation_coverage_ratio']['baseline_vt']:.3f}, "
        f"llmrag={summary['interpretability_metrics']['explanation_coverage_ratio']['llmrag']:.3f}"
    )
    typer.echo(
        f"Coverage (LLM+RAG evidence present): {summary['interpretability_metrics']['llmrag_explanations_present_count']}/{summary['total_samples_joined']}"
    )
    typer.echo(
        f"Grounding≥2 citations (LLM+RAG):     {summary['interpretability_metrics']['llmrag_grounding_at_least_two_references_count']}/{summary['interpretability_metrics']['llmrag_explanations_present_count']}"
    )
    typer.echo(
        f"Grounding ratio (LLM+RAG): {summary['interpretability_metrics']['llmrag_grounding_ratio']:.3f}"
    )
    typer.echo(
        f"RuleMatch ratio: baseline={summary['interpretability_metrics']['rule_match_consistency_ratio']['baseline']:.3f}, "
        f"baseline+VT={summary['interpretability_metrics']['rule_match_consistency_ratio']['baseline_vt']:.3f}"
    )
    typer.echo("-- Guardrails --")
    typer.echo(
        f"Abstentions (LLM+RAG label='unknown'): {summary['interpretability_metrics']['llmrag_abstentions_count']}/{summary['total_samples_joined']}"
    )
    typer.echo("-- Composite (weights: ")
    typer.echo(
        f"alpha={summary['composite_and_component_scores']['weighting_coefficients']['alpha_accuracy_weight']:.3f}, "
        f"beta={summary['composite_and_component_scores']['weighting_coefficients']['beta_efficiency_weight']:.3f}, "
        f"gamma={summary['composite_and_component_scores']['weighting_coefficients']['gamma_interpretability_weight']:.3f})"
    )
    typer.echo(
        f"Baseline:    {summary['composite_and_component_scores']['baseline']['composite_score']:.4f}  "
        f"(Acc={summary['composite_and_component_scores']['baseline']['accuracy_score']:.3f}, "
        f"Eff^-1={summary['composite_and_component_scores']['baseline']['efficiency_score']:.3f}, "
        f"Intp={summary['composite_and_component_scores']['baseline']['interpretability_score']:.3f})"
    )
    typer.echo(
        f"Baseline+VT: {summary['composite_and_component_scores']['baseline_vt']['composite_score']:.4f}  "
        f"(Acc={summary['composite_and_component_scores']['baseline_vt']['accuracy_score']:.3f}, "
        f"Eff^-1={summary['composite_and_component_scores']['baseline_vt']['efficiency_score']:.3f}, "
        f"Intp={summary['composite_and_component_scores']['baseline_vt']['interpretability_score']:.3f})"
    )
    typer.echo(
        f"LLM+RAG:     {summary['composite_and_component_scores']['llmrag']['composite_score']:.4f}  "
        f"(Acc={summary['composite_and_component_scores']['llmrag']['accuracy_score']:.3f}, "
        f"Eff^-1={summary['composite_and_component_scores']['llmrag']['efficiency_score']:.3f}, "
        f"Intp={summary['composite_and_component_scores']['llmrag']['interpretability_score']:.3f})"
    )
    typer.echo(f"CSV:  {summary['output_csv_path']}")
    if "output_json_path" in summary:
        typer.echo(f"JSON: {summary['output_json_path']}")
