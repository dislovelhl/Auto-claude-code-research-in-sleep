"""
GovernedAnsibleBench — Full Evaluation Harness with Ablation Studies

Implements:
1. Full evaluation across all baselines (including real ansible-lint + OPA)
2. Ablation study: which contextual features drive ACGS improvements
3. Proper metrics: accuracy, macro-F1, per-class P/R/F1, confusion matrix
4. Context-sensitivity tests: same playbook in dev vs prod, normal vs high SLO
5. Results saved to results/full_eval_results.json
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "baselines"))

from baselines.real_baselines import (
    ACGSTierClassifierBaseline,
    AblationConfig,
    RealAnsibleLintBaseline,
    RealCheckModeBaseline,
    RealOPABaseline,
)
from risk_tier_classifier import Tier

TIER_ORDER = [t.value for t in Tier]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(predictions: list[str], ground_truth: list[str]) -> dict[str, Any]:
    """Compute accuracy, per-class P/R/F1, macro-F1, and confusion matrix."""
    assert len(predictions) == len(ground_truth), "Length mismatch"
    n = len(predictions)
    accuracy = sum(p == g for p, g in zip(predictions, ground_truth)) / n if n > 0 else 0.0

    per_class: dict[str, dict[str, float]] = {}
    for tier in TIER_ORDER:
        tp = sum(p == tier and g == tier for p, g in zip(predictions, ground_truth))
        fp = sum(p == tier and g != tier for p, g in zip(predictions, ground_truth))
        fn = sum(p != tier and g == tier for p, g in zip(predictions, ground_truth))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        support = sum(g == tier for g in ground_truth)
        per_class[tier] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "support": support,
        }

    present_tiers = [t for t in TIER_ORDER if per_class[t]["support"] > 0]
    macro_f1 = sum(per_class[t]["f1"] for t in present_tiers) / len(present_tiers) if present_tiers else 0.0

    # Confusion matrix: rows=predicted, cols=actual
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for p, g in zip(predictions, ground_truth):
        confusion[p][g] += 1

    return {
        "accuracy": round(accuracy, 3),
        "macro_f1": round(macro_f1, 3),
        "per_class": per_class,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
        "n_samples": n,
    }


# ---------------------------------------------------------------------------
# Context sensitivity test
# ---------------------------------------------------------------------------

def build_context_variant(
    base_task: dict[str, Any], variant: str
) -> dict[str, Any]:
    """Generate context variants for sensitivity analysis."""
    import copy
    task = copy.deepcopy(base_task)
    if variant == "dev_low_criticality":
        for h in task.get("inventory", {}).get("hosts", []):
            h["environment"] = "development"
            h["criticality"] = "tier3"
            h["slo_burn_rate_1h"] = 0.0
            h["in_maintenance_window"] = False
    elif variant == "prod_tier1_high_slo":
        for h in task.get("inventory", {}).get("hosts", []):
            h["environment"] = "production"
            h["criticality"] = "tier1"
            h["slo_burn_rate_1h"] = 80.0
            h["in_maintenance_window"] = False
    elif variant == "prod_maintenance_window":
        for h in task.get("inventory", {}).get("hosts", []):
            h["environment"] = "production"
            h["criticality"] = "tier2"
            h["slo_burn_rate_1h"] = 5.0
            h["in_maintenance_window"] = True
    return task


def run_context_sensitivity(
    tasks: list[dict[str, Any]],
    classifier: ACGSTierClassifierBaseline,
) -> list[dict[str, Any]]:
    """Test how tier decisions change across inventory context variants."""
    results = []
    variants = ["dev_low_criticality", "prod_tier1_high_slo", "prod_maintenance_window"]
    for task_def in tasks[:5]:  # Use first 5 tasks for sensitivity analysis
        task_id = task_def.get("task_id", "unknown")
        row: dict[str, Any] = {"task_id": task_id, "variants": {}}
        for variant in variants:
            variant_task = build_context_variant(task_def, variant)
            result = classifier.evaluate(variant_task)
            row["variants"][variant] = result.get("tier_guess", "unknown")
        results.append(row)
    return results


# ---------------------------------------------------------------------------
# Main evaluation runner
# ---------------------------------------------------------------------------

def load_all_tasks(task_base: Path) -> list[dict[str, Any]]:
    tasks = []
    for task_file in sorted(task_base.rglob("*.json")):
        with open(task_file, encoding="utf-8") as f:
            task_def = json.load(f)
            task_def["_source_file"] = str(task_file)
            tasks.append(task_def)
    return tasks


def run_full_evaluation(
    task_base: Path = Path("tasks"),
    output_path: Path = Path("results/full_eval_results.json"),
) -> dict[str, Any]:
    tasks = load_all_tasks(task_base)
    if not tasks:
        return {"error": "No tasks found", "task_base": str(task_base)}

    # Baselines to evaluate
    baselines = [
        RealAnsibleLintBaseline(),
        RealCheckModeBaseline(),
        RealOPABaseline(),
        ACGSTierClassifierBaseline(AblationConfig.full()),
    ]

    # Ablation variants of ACGS
    ablations = [
        ("acgs-no-inventory", ACGSTierClassifierBaseline(AblationConfig.no_inventory())),
        ("acgs-no-context", ACGSTierClassifierBaseline(AblationConfig.no_context())),
        ("acgs-no-slo", ACGSTierClassifierBaseline(
            AblationConfig(use_slo_context=False)
        )),
        ("acgs-no-blast-radius", ACGSTierClassifierBaseline(
            AblationConfig(use_blast_radius=False)
        )),
    ]

    task_results = []
    for task_def in tasks:
        gt = task_def.get("expected_tier", "auto-approve")
        row: dict[str, Any] = {
            "task_id": task_def.get("task_id", "unknown"),
            "category": task_def.get("category", "unknown"),
            "ground_truth": gt,
            "difficulty": task_def.get("difficulty", "medium"),
            "baselines": {},
            "ablations": {},
        }
        for bl in baselines:
            start = time.time()
            row["baselines"][bl.name] = bl.evaluate(task_def)
            row["baselines"][bl.name]["latency_ms"] = round((time.time() - start) * 1000, 1)

        for abl_name, abl_clf in ablations:
            row["ablations"][abl_name] = abl_clf.evaluate(task_def)

        task_results.append(row)

    # Aggregate metrics
    gt_labels = [r["ground_truth"] for r in task_results]
    aggregate_metrics: dict[str, Any] = {}

    for bl in baselines:
        preds = [r["baselines"][bl.name].get("tier_guess", "auto-approve") for r in task_results]
        aggregate_metrics[bl.name] = compute_metrics(preds, gt_labels)

    for abl_name, _ in ablations:
        preds = [r["ablations"][abl_name].get("tier_guess", "auto-approve") for r in task_results]
        aggregate_metrics[abl_name] = compute_metrics(preds, gt_labels)

    # Context sensitivity analysis
    acgs_full = ACGSTierClassifierBaseline(AblationConfig.full())
    context_sensitivity = run_context_sensitivity(tasks, acgs_full)

    result = {
        "n_tasks": len(tasks),
        "timestamp": time.time(),
        "task_results": task_results,
        "aggregate_metrics": aggregate_metrics,
        "context_sensitivity": context_sensitivity,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    return result


def print_summary(results: dict[str, Any]) -> None:
    print(f"\n{'='*60}")
    print(f"GovernedAnsibleBench Evaluation Summary")
    print(f"{'='*60}")
    print(f"Tasks evaluated: {results.get('n_tasks', 0)}")
    print()
    print(f"{'Baseline/Ablation':35s} {'Accuracy':>10} {'Macro-F1':>10}")
    print(f"{'-'*55}")
    for name, m in results.get("aggregate_metrics", {}).items():
        acc = m.get("accuracy", 0.0) * 100
        mf1 = m.get("macro_f1", 0.0) * 100
        print(f"  {name:33s} {acc:9.1f}% {mf1:9.1f}%")

    print()
    print("Context sensitivity (ACGS full — tier changes across inventory variants):")
    for row in results.get("context_sensitivity", []):
        variants = row.get("variants", {})
        variants_str = " | ".join(f"{k}={v}" for k, v in variants.items())
        print(f"  {row['task_id']}: {variants_str}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GovernedAnsibleBench Full Evaluation")
    parser.add_argument("--tasks", default="tasks", help="Task directory")
    parser.add_argument("--output", default="results/full_eval_results.json")
    args = parser.parse_args()

    results = run_full_evaluation(Path(args.tasks), Path(args.output))
    print_summary(results)
    print(f"\nFull results saved to: {args.output}")
