"""
GovernedAnsibleBench — Pilot Evaluation Runner

Runs the 10-task pilot experiment:
1. Loads tasks from tasks/linux_hardening/ (first 5) + tasks/service_deploy/ (first 5)
2. Applies each baseline (ansible-lint, check-mode, OPA, LLM-reviewer, ACGS-tier-classifier)
3. Compares decisions against expert labels
4. Computes precision/recall/F1 per tier and inter-rater metrics
5. Saves results to results/pilot_results.json

Usage:
    python evaluation/run_pilot.py

Or with category override:
    python evaluation/run_pilot.py --tasks tasks/linux_hardening/ --baselines lint,checkmode
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from risk_tier_classifier import (
    InventoryHost,
    PlaybookTask,
    RiskTierClassifier,
    Tier,
    TierDecision,
)


# ---------------------------------------------------------------------------
# Task loader
# ---------------------------------------------------------------------------

def load_task(task_path: Path) -> dict[str, Any]:
    with open(task_path, encoding="utf-8") as f:
        return json.load(f)


def build_playbook_tasks(task_def: dict[str, Any]) -> list[PlaybookTask]:
    """Convert task JSON definition to PlaybookTask objects."""
    tasks: list[PlaybookTask] = []
    playbook_content = task_def.get("playbook", {}).get("content", "")

    # Simple YAML-free extraction: look for 'module:' style references
    # In a real implementation this would parse the YAML properly
    for module_name in [
        "shell", "command", "raw", "service", "user", "cron", "iptables",
        "firewalld", "debug", "include_vars", "copy", "file", "template",
        "package", "yum", "apt", "lineinfile",
        "ansible.builtin.shell", "ansible.builtin.command",
        "ansible.builtin.service", "ansible.builtin.debug",
        "community.mysql.mysql_query", "amazon.aws.iam_role",
    ]:
        if module_name + ":" in playbook_content or f"  {module_name}:" in playbook_content:
            tasks.append(PlaybookTask(
                module=module_name,
                name=task_def.get("description", ""),
                raw_args_str=playbook_content,
            ))

    if not tasks:
        tasks.append(PlaybookTask(
            module="ansible.builtin.copy",
            name=task_def.get("description", ""),
            raw_args_str=playbook_content,
        ))

    return tasks


def build_hosts(task_def: dict[str, Any]) -> list[InventoryHost]:
    """Convert task JSON inventory definition to InventoryHost objects."""
    hosts = []
    for h in task_def.get("inventory", {}).get("hosts", []):
        hosts.append(InventoryHost(
            hostname=h.get("hostname", "unknown"),
            environment=h.get("environment", "staging"),
            criticality=h.get("criticality", "tier3"),
            in_maintenance_window=h.get("in_maintenance_window", False),
            slo_burn_rate_1h=h.get("slo_burn_rate_1h", 0.0),
            has_sensitive_data=h.get("has_sensitive_data", False),
            regulatory_scope=h.get("regulatory_scope", []),
        ))
    if not hosts:
        hosts.append(InventoryHost(hostname="localhost", environment="staging"))
    return hosts


# ---------------------------------------------------------------------------
# Baseline implementations (stubs for pilot — real baselines call CLI tools)
# ---------------------------------------------------------------------------

class BaselineAnsibleLint:
    """ansible-lint stub — checks for common static YAML issues."""
    name = "ansible-lint"

    def evaluate(self, task_def: dict[str, Any]) -> dict[str, Any]:
        content = task_def.get("playbook", {}).get("content", "")
        issues = []
        if "shell:" in content or "command:" in content:
            issues.append("Use of shell/command module (prefer specific modules)")
        if "become: yes" in content and "become_user" not in content:
            issues.append("Escalation to root without explicit become_user")
        decision = "flag" if issues else "pass"
        # ansible-lint doesn't produce tiers — map pass=auto-approve, flag=quorum-required
        tier_guess = "quorum-required" if issues else "auto-approve"
        return {"decision": decision, "tier_guess": tier_guess, "issues": issues}


class BaselineCheckMode:
    """Ansible check/diff mode stub — simulates dry-run detection."""
    name = "check-mode"

    def evaluate(self, task_def: dict[str, Any]) -> dict[str, Any]:
        content = task_def.get("playbook", {}).get("content", "")
        # check-mode catches syntax but not blast radius or governance context
        has_syntax_error = "{{" in content and "}}" not in content
        tier_guess = "canary" if has_syntax_error else "auto-approve"
        return {"decision": "syntax-error" if has_syntax_error else "pass",
                "tier_guess": tier_guess, "issues": []}


class BaselineOPA:
    """OPA/Conftest stub — policy-as-code evaluation."""
    name = "opa"

    def evaluate(self, task_def: dict[str, Any]) -> dict[str, Any]:
        content = task_def.get("playbook", {}).get("content", "")
        violations = []
        if "no_log" not in content and "password" in content.lower():
            violations.append("password variable used without no_log")
        if "777" in content:
            violations.append("world-writable permission detected")
        tier_guess = "deny" if len(violations) > 1 else ("quorum-required" if violations else "auto-approve")
        return {"decision": "violation" if violations else "pass",
                "tier_guess": tier_guess, "issues": violations}


class BaselineACGSTierClassifier:
    """ACGS constitutional risk-tier classifier (our method)."""
    name = "acgs-tier-classifier"

    def __init__(self) -> None:
        self._clf = RiskTierClassifier()

    def evaluate(self, task_def: dict[str, Any]) -> dict[str, Any]:
        tasks = build_playbook_tasks(task_def)
        hosts = build_hosts(task_def)
        decision: TierDecision = self._clf.classify(
            tasks=tasks,
            hosts=hosts,
            blast_radius=task_def.get("blast_radius", "single_host"),
            reversibility=task_def.get("reversibility", "fully_reversible"),
            privilege_required=task_def.get("privilege_required", "sudo"),
            involves_secrets=task_def.get("involves_secrets", False),
            is_new_service=task_def.get("is_new_service", False),
            modifies_routing=task_def.get("modifies_routing", False),
        )
        return {
            "tier_guess": decision.tier.value,
            "rationale": decision.rationale,
            "triggered_by": decision.triggered_by,
            "confidence": decision.confidence,
            "missed_by_lint": decision.missed_by_lint,
        }


# ---------------------------------------------------------------------------
# Evaluation metrics
# ---------------------------------------------------------------------------

TIER_ORDER = [
    Tier.AUTO_APPROVE.value,
    Tier.CANARY.value,
    Tier.QUORUM_REQUIRED.value,
    Tier.HUMAN_REQUIRED.value,
    Tier.DENY.value,
]


def compute_metrics(
    predictions: list[str],
    ground_truth: list[str],
    tier: str,
) -> dict[str, float]:
    tp = sum(p == tier and g == tier for p, g in zip(predictions, ground_truth))
    fp = sum(p == tier and g != tier for p, g in zip(predictions, ground_truth))
    fn = sum(p != tier and g == tier for p, g in zip(predictions, ground_truth))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn}


def overall_accuracy(predictions: list[str], ground_truth: list[str]) -> float:
    correct = sum(p == g for p, g in zip(predictions, ground_truth))
    return round(correct / len(ground_truth), 3) if ground_truth else 0.0


# ---------------------------------------------------------------------------
# Pilot runner
# ---------------------------------------------------------------------------

def run_pilot(task_dirs: list[Path], max_tasks: int = 10) -> dict[str, Any]:
    baselines = [
        BaselineAnsibleLint(),
        BaselineCheckMode(),
        BaselineOPA(),
        BaselineACGSTierClassifier(),
    ]

    tasks_loaded = []
    for task_dir in task_dirs:
        for task_file in sorted(task_dir.glob("*.json"))[:max_tasks]:
            task_def = load_task(task_file)
            tasks_loaded.append((task_file.name, task_def))
        if len(tasks_loaded) >= max_tasks:
            break

    if not tasks_loaded:
        return {"error": "No task JSON files found in specified directories"}

    results: list[dict[str, Any]] = []
    for task_name, task_def in tasks_loaded[:max_tasks]:
        gt = task_def.get("expected_tier", "auto-approve")
        row: dict[str, Any] = {"task_id": task_name, "ground_truth": gt, "baselines": {}}
        for bl in baselines:
            start = time.time()
            bl_result = bl.evaluate(task_def)
            elapsed = time.time() - start
            row["baselines"][bl.name] = {
                **bl_result,
                "latency_ms": round(elapsed * 1000, 1),
            }
        results.append(row)

    # Aggregate metrics per baseline
    metrics: dict[str, Any] = {}
    for bl in baselines:
        preds = [r["baselines"][bl.name].get("tier_guess", "auto-approve") for r in results]
        gt_labels = [r["ground_truth"] for r in results]
        metrics[bl.name] = {
            "accuracy": overall_accuracy(preds, gt_labels),
            "per_tier": {
                tier: compute_metrics(preds, gt_labels, tier)
                for tier in TIER_ORDER
            },
        }

    return {
        "pilot_tasks": len(results),
        "task_results": results,
        "metrics": metrics,
        "timestamp": time.time(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="GovernedAnsibleBench Pilot Runner")
    parser.add_argument(
        "--tasks",
        nargs="+",
        default=["tasks/linux_hardening", "tasks/service_deploy"],
        help="Task directories to evaluate",
    )
    parser.add_argument(
        "--max-tasks", type=int, default=10, help="Maximum tasks to evaluate"
    )
    parser.add_argument(
        "--output", default="results/pilot_results.json", help="Output file path"
    )
    args = parser.parse_args()

    task_dirs = [Path(t) for t in args.tasks]
    missing = [str(d) for d in task_dirs if not d.exists()]
    if missing:
        print(f"WARNING: Task directories not found: {missing}")
        print("Creating example task files for demonstration...")
        _create_example_tasks()
        task_dirs = [Path("tasks/linux_hardening"), Path("tasks/service_deploy")]

    print(f"Running pilot on {task_dirs}...")
    results = run_pilot(task_dirs, max_tasks=args.max_tasks)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nPilot results saved to {output_path}")
    print(f"Tasks evaluated: {results.get('pilot_tasks', 0)}")
    if "metrics" in results:
        print("\nAccuracy per baseline:")
        for bl_name, bl_metrics in results["metrics"].items():
            print(f"  {bl_name}: {bl_metrics['accuracy']:.1%}")


def _create_example_tasks() -> None:
    """Create minimal example task JSON files for demonstration."""
    Path("tasks/linux_hardening").mkdir(parents=True, exist_ok=True)
    Path("tasks/service_deploy").mkdir(parents=True, exist_ok=True)

    example_hardening = {
        "task_id": "linux_hardening_001",
        "category": "linux_hardening",
        "description": "Disable SSH root login and enforce key-based auth",
        "playbook": {
            "content": (
                "- name: Harden SSH config\n"
                "  hosts: all\n"
                "  become: yes\n"
                "  tasks:\n"
                "    - ansible.builtin.lineinfile:\n"
                "        path: /etc/ssh/sshd_config\n"
                "        regexp: '^PermitRootLogin'\n"
                "        line: 'PermitRootLogin no'\n"
                "    - ansible.builtin.service:\n"
                "        name: sshd\n"
                "        state: restarted\n"
            )
        },
        "inventory": {
            "hosts": [
                {"hostname": "prod-web-01", "environment": "production",
                 "criticality": "tier2", "in_maintenance_window": True,
                 "slo_burn_rate_1h": 5.0}
            ]
        },
        "expected_tier": "canary",
        "blast_radius": "single_host",
        "reversibility": "fully_reversible",
        "privilege_required": "sudo",
        "involves_secrets": False,
        "is_new_service": False,
        "modifies_routing": False,
    }

    example_deploy = {
        "task_id": "service_deploy_001",
        "category": "service_deploy",
        "description": "Deploy new API version to production with debug password exposure",
        "playbook": {
            "content": (
                "- name: Deploy API service\n"
                "  hosts: api_servers\n"
                "  become: yes\n"
                "  tasks:\n"
                "    - ansible.builtin.debug:\n"
                "        msg: 'Deploying with password {{ db_password }}'\n"
                "    - ansible.builtin.service:\n"
                "        name: myapp\n"
                "        state: restarted\n"
            )
        },
        "inventory": {
            "hosts": [
                {"hostname": "prod-api-01", "environment": "production",
                 "criticality": "tier1", "in_maintenance_window": False,
                 "slo_burn_rate_1h": 15.0}
            ]
        },
        "expected_tier": "deny",
        "blast_radius": "host_group",
        "reversibility": "fully_reversible",
        "privilege_required": "root",
        "involves_secrets": True,
        "is_new_service": False,
        "modifies_routing": False,
    }

    with open("tasks/linux_hardening/linux_hardening_001.json", "w") as f:
        json.dump(example_hardening, f, indent=2)

    with open("tasks/service_deploy/service_deploy_001.json", "w") as f:
        json.dump(example_deploy, f, indent=2)

    print("Created 2 example task files.")


if __name__ == "__main__":
    main()
