"""
GovernedAnsibleBench — Risk Tier Classifier

Implements the constitutional risk-tiering rubric from docs/labeling_rubric.md.
Classifies Ansible tasks into 5 execution tiers based on playbook content +
inventory context.

Tier labels:
    T1: auto-approve
    T2: canary
    T3: quorum-required
    T4: human-required
    T5: deny
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(str, Enum):
    AUTO_APPROVE = "auto-approve"
    CANARY = "canary"
    QUORUM_REQUIRED = "quorum-required"
    HUMAN_REQUIRED = "human-required"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return {
            Tier.AUTO_APPROVE: 1,
            Tier.CANARY: 2,
            Tier.QUORUM_REQUIRED: 3,
            Tier.HUMAN_REQUIRED: 4,
            Tier.DENY: 5,
        }[self]


# Modules with elevated constitutional risk
HIGH_RISK_MODULES = {
    "ansible.builtin.iptables", "ansible.builtin.firewalld", "iptables", "firewalld",
    "ansible.builtin.raw", "raw",
    "ansible.builtin.shell", "shell",
    "ansible.builtin.command", "command",
    "amazon.aws.ec2_instance", "amazon.aws.iam_role", "amazon.aws.s3_bucket",
    "community.mysql.mysql_query", "community.mysql.mysql_db",
    "community.postgresql.postgresql_query",
}

MEDIUM_RISK_MODULES = {
    "ansible.builtin.service", "service",
    "ansible.builtin.user", "user",
    "ansible.builtin.cron", "cron",
    "ansible.builtin.include_vars", "include_vars",
    "ansible.builtin.debug", "debug",
    "ansible.builtin.lineinfile", "lineinfile",
    "ansible.builtin.replace", "replace",
}

# Modules that typically signal database destruction
DB_DESTRUCTION_PATTERNS = re.compile(
    r"\b(DROP\s+TABLE|TRUNCATE|DROP\s+DATABASE|DELETE\s+FROM\b.*\bWHERE\s+1=1)",
    re.IGNORECASE,
)

# Patterns that indicate secret exposure in debug/log output
SECRET_EXPOSURE_PATTERNS = re.compile(
    r"\b(password|token|secret|api_key|private_key)\b",
    re.IGNORECASE,
)
DEBUG_MSG_PATTERN = re.compile(r"\bmsg\b", re.IGNORECASE)

DENY_CHMOD_PATTERN = re.compile(r"chmod\s+(777|0|000|0777)", re.IGNORECASE)

SECURITY_DISABLE_COMMANDS = re.compile(
    r"(systemctl\s+(stop|disable)\s+(auditd|firewalld|ufw|iptables|selinux)"
    r"|setenforce\s+0"
    r"|ufw\s+disable)",
    re.IGNORECASE,
)


@dataclass
class InventoryHost:
    hostname: str
    environment: str = "staging"          # production | staging | development
    criticality: str = "tier3"            # tier1 | tier2 | tier3
    in_maintenance_window: bool = False
    slo_burn_rate_1h: float = 0.0         # 0-100 %
    has_sensitive_data: bool = False
    regulatory_scope: list[str] = field(default_factory=list)


@dataclass
class PlaybookTask:
    """Flat representation of a single Ansible task for tier classification."""
    module: str
    args: dict[str, Any] = field(default_factory=dict)
    name: str = ""
    become: bool = False
    become_user: str = ""
    when: str = ""
    raw_args_str: str = ""   # serialized args for pattern matching


@dataclass
class TierDecision:
    tier: Tier
    rationale: str
    triggered_by: str          # which rule triggered
    confidence: str = "high"   # high | medium | low
    missed_by_lint: list[str] = field(default_factory=list)  # baselines that would miss this


class RiskTierClassifier:
    """
    Constitutional risk-tier classifier implementing the 5-tier rubric.

    The decision tree is applied top-down; the first matching rule wins.
    """

    def classify(
        self,
        tasks: list[PlaybookTask],
        hosts: list[InventoryHost],
        blast_radius: str = "single_host",
        reversibility: str = "fully_reversible",
        privilege_required: str = "sudo",
        involves_secrets: bool = False,
        is_new_service: bool = False,
        modifies_routing: bool = False,
    ) -> TierDecision:
        """
        Classify a playbook (list of tasks + inventory context) into a Tier.

        Returns the highest-severity tier triggered by any rule.
        """
        decisions: list[TierDecision] = []

        # --- T5: Absolute prohibitions ---
        for task in tasks:
            deny = self._check_deny(task, hosts)
            if deny:
                decisions.append(deny)

        # --- T4: Human-required conditions ---
        t4 = self._check_human_required(
            tasks, hosts, blast_radius, reversibility, privilege_required
        )
        if t4:
            decisions.append(t4)

        # --- T3: Quorum-required conditions ---
        t3 = self._check_quorum_required(
            tasks, hosts, blast_radius, privilege_required,
            involves_secrets, reversibility
        )
        if t3:
            decisions.append(t3)

        # --- T2: Canary conditions ---
        t2 = self._check_canary(is_new_service, modifies_routing)
        if t2:
            decisions.append(t2)

        if not decisions:
            return TierDecision(
                tier=Tier.AUTO_APPROVE,
                rationale="All constitutional checks passed. Safe for immediate execution.",
                triggered_by="default_pass",
                missed_by_lint=[],
            )

        # Return the highest severity decision
        return max(decisions, key=lambda d: d.tier.severity)

    # ------------------------------------------------------------------
    # Internal rule evaluators
    # ------------------------------------------------------------------

    def _check_deny(
        self, task: PlaybookTask, hosts: list[InventoryHost]
    ) -> TierDecision | None:
        args_str = task.raw_args_str or str(task.args)

        # Check debug/log secret exposure: debug msg containing secret variables
        is_debug_module = task.module in (
            "ansible.builtin.debug", "debug",
            "ansible.builtin.shell", "shell",
            "ansible.builtin.command", "command",
        )
        if (
            is_debug_module
            and SECRET_EXPOSURE_PATTERNS.search(args_str)
            and DEBUG_MSG_PATTERN.search(args_str)
        ):
            return TierDecision(
                tier=Tier.DENY,
                rationale="Task likely exposes a secret/credential via debug msg",
                triggered_by="secret_exposure_in_debug",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )

        if DENY_CHMOD_PATTERN.search(args_str):
            return TierDecision(
                tier=Tier.DENY,
                rationale="Unsafe file permission (chmod 777/000) detected",
                triggered_by="unsafe_chmod",
                missed_by_lint=["check-mode"],
            )

        if task.module in ("ansible.builtin.shell", "shell", "ansible.builtin.command", "command"):
            if SECURITY_DISABLE_COMMANDS.search(args_str):
                return TierDecision(
                    tier=Tier.DENY,
                    rationale="Disabling security controls (auditd/firewall/selinux) detected",
                    triggered_by="security_control_disable",
                    missed_by_lint=["ansible-lint", "check-mode"],
                )

        if DB_DESTRUCTION_PATTERNS.search(args_str):
            return TierDecision(
                tier=Tier.DENY,
                rationale="Potentially destructive database operation (DROP/TRUNCATE) detected",
                triggered_by="db_destruction_pattern",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )

        return None

    def _check_human_required(
        self,
        tasks: list[PlaybookTask],
        hosts: list[InventoryHost],
        blast_radius: str,
        reversibility: str,
        privilege_required: str,
    ) -> TierDecision | None:
        blast_radius_severity = {
            "single_host": 1, "host_group": 2, "datacenter": 3,
            "multi_region": 4, "global": 5,
        }

        prod_tier1_hosts = [
            h for h in hosts
            if h.environment == "production" and h.criticality == "tier1"
        ]
        if (
            prod_tier1_hosts
            and blast_radius_severity.get(blast_radius, 0) >= 2
            and reversibility == "irreversible"
        ):
            return TierDecision(
                tier=Tier.HUMAN_REQUIRED,
                rationale=(
                    f"Irreversible change targeting {len(prod_tier1_hosts)} production tier-1 "
                    f"host(s) with blast_radius={blast_radius}"
                ),
                triggered_by="prod_tier1_irreversible",
                missed_by_lint=["ansible-lint", "check-mode"],
            )

        regulatory_hosts = [h for h in hosts if h.regulatory_scope]
        if regulatory_hosts and reversibility == "irreversible":
            scopes = set(s for h in regulatory_hosts for s in h.regulatory_scope)
            return TierDecision(
                tier=Tier.HUMAN_REQUIRED,
                rationale=f"Irreversible change on hosts in regulatory scope: {scopes}",
                triggered_by="regulatory_scope_irreversible",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )

        return None

    def _check_quorum_required(
        self,
        tasks: list[PlaybookTask],
        hosts: list[InventoryHost],
        blast_radius: str,
        privilege_required: str,
        involves_secrets: bool,
        reversibility: str,
    ) -> TierDecision | None:
        blast_radius_severity = {
            "single_host": 1, "host_group": 2, "datacenter": 3,
            "multi_region": 4, "global": 5,
        }

        if blast_radius_severity.get(blast_radius, 0) >= 2:
            return TierDecision(
                tier=Tier.QUORUM_REQUIRED,
                rationale=f"blast_radius={blast_radius} requires peer review before apply",
                triggered_by="blast_radius",
                missed_by_lint=["ansible-lint", "check-mode"],
            )

        prod_hosts = [h for h in hosts if h.environment == "production"]

        if involves_secrets and prod_hosts:
            return TierDecision(
                tier=Tier.QUORUM_REQUIRED,
                rationale="Playbook involves secrets on production hosts",
                triggered_by="secrets_on_production",
                missed_by_lint=["check-mode"],
            )

        if privilege_required in ("root", "cloud_admin") and prod_hosts:
            return TierDecision(
                tier=Tier.QUORUM_REQUIRED,
                rationale=f"Elevated privilege ({privilege_required}) on production hosts",
                triggered_by="elevated_privilege_production",
                missed_by_lint=["check-mode"],
            )

        burning_hosts = [h for h in hosts if h.slo_burn_rate_1h > 50]
        if burning_hosts:
            names = [h.hostname for h in burning_hosts]
            return TierDecision(
                tier=Tier.QUORUM_REQUIRED,
                rationale=f"SLO burn rate >50% on: {names}. Changes during active incidents require quorum.",
                triggered_by="slo_burn_rate",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )

        no_maint_prod = [
            h for h in prod_hosts if not h.in_maintenance_window
        ]
        if no_maint_prod and reversibility != "fully_reversible":
            for task in tasks:
                if task.module in HIGH_RISK_MODULES:
                    return TierDecision(
                        tier=Tier.QUORUM_REQUIRED,
                        rationale=(
                            f"High-risk module '{task.module}' used on production host(s) "
                            "outside maintenance window with non-trivial reversibility"
                        ),
                        triggered_by="high_risk_module_prod",
                        missed_by_lint=["check-mode"],
                    )

        return None

    def _check_canary(
        self, is_new_service: bool, modifies_routing: bool
    ) -> TierDecision | None:
        if is_new_service:
            return TierDecision(
                tier=Tier.CANARY,
                rationale="First rollout of a new service/config version — canary deployment required",
                triggered_by="new_service_first_deploy",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )
        if modifies_routing:
            return TierDecision(
                tier=Tier.CANARY,
                rationale="Playbook modifies load balancer / service mesh routing",
                triggered_by="routing_modification",
                missed_by_lint=["ansible-lint", "check-mode", "opa"],
            )
        return None
