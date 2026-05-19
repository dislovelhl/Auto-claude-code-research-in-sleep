"""
GovernedAnsibleBench — Governance Receipt Emitter

Implements the Ansible callback plugin that emits signed governance receipt
bundles (JSONL format) for each task execution. Receipts include:

- Playbook hash + inventory snapshot
- AgentDNA tier decision + rationale (from RiskTierClassifier)
- Ansible Runner job_events log entries
- Rollback DAG reference (if applicable)

Usage as Ansible callback plugin:
    Add to ansible.cfg:
        [defaults]
        callback_plugins = governed_ansible_bench/receipts/
        callbacks_enabled = governance_receipt_emitter

Or import directly:
    from governed_ansible_bench.receipts.governance_receipt_emitter import GovernanceReceiptEmitter
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    from ansible.plugins.callback import CallbackBase  # type: ignore
    ANSIBLE_AVAILABLE = True
except ImportError:
    ANSIBLE_AVAILABLE = False
    # Stub for environments without Ansible installed
    class CallbackBase:  # type: ignore
        pass


@dataclass
class GovernanceVote:
    """A single agent's constitutional vote on a proposed playbook execution."""
    agent_id: str
    decision: str        # approve | reject | abstain
    rationale: str
    tier_assigned: str
    constitutional_rules_checked: list[str]
    timestamp: float = field(default_factory=time.time)
    signature: str = ""  # Ed25519 hex (stub; real impl uses cryptography package)


@dataclass
class GovernanceReceipt:
    """
    Complete governance receipt bundle binding:
    - The proposed playbook (hash-verified)
    - Constitutional governance decision
    - Execution evidence from Ansible Runner
    """
    receipt_id: str
    playbook_hash: str                  # SHA-256 of playbook YAML content
    inventory_snapshot_hash: str        # SHA-256 of serialized inventory
    tier_decision: str                  # auto-approve | canary | quorum-required | human-required | deny
    tier_rationale: str
    triggered_by: str
    quorum_votes: list[GovernanceVote]
    execution_events: list[dict[str, Any]]   # Ansible Runner job_events
    rollback_dag_hash: str | None
    wall_clock_start: float
    wall_clock_end: float | None
    execution_status: str = "pending"   # pending | approved | denied | executed | failed
    missed_by_baselines: list[str] = field(default_factory=list)

    @property
    def wall_clock_duration_s(self) -> float | None:
        if self.wall_clock_end is None:
            return None
        return self.wall_clock_end - self.wall_clock_start

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_jsonl(cls, line: str) -> "GovernanceReceipt":
        data = json.loads(line)
        data["quorum_votes"] = [GovernanceVote(**v) for v in data["quorum_votes"]]
        return cls(**data)


class ReceiptStore:
    """Append-only JSONL store for governance receipts."""

    def __init__(self, store_path: str | Path = "receipts/run_receipts.jsonl"):
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, receipt: GovernanceReceipt) -> None:
        with open(self.store_path, "a", encoding="utf-8") as fh:
            fh.write(receipt.to_jsonl() + "\n")

    def read_all(self) -> list[GovernanceReceipt]:
        if not self.store_path.exists():
            return []
        receipts = []
        with open(self.store_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    receipts.append(GovernanceReceipt.from_jsonl(line))
        return receipts

    def read_by_playbook_hash(self, playbook_hash: str) -> list[GovernanceReceipt]:
        return [r for r in self.read_all() if r.playbook_hash == playbook_hash]


def hash_content(content: str) -> str:
    """Return SHA-256 hex digest of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_receipt_id() -> str:
    """Generate a unique receipt ID."""
    import uuid
    return f"rcpt_{uuid.uuid4().hex[:12]}"


class GovernanceReceiptEmitter(CallbackBase):
    """
    Ansible callback plugin that emits governance receipts for each play.

    Install by adding to ansible.cfg:
        [defaults]
        callback_plugins = path/to/governed_ansible_bench/receipts/
        callbacks_enabled = governance_receipt_emitter
    """

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "governance_receipt_emitter"
    CALLBACK_NEEDS_WHITELIST = False

    def __init__(self) -> None:
        super().__init__()
        store_path = os.environ.get(
            "GOVERNED_RECEIPT_STORE", "receipts/run_receipts.jsonl"
        )
        self._store = ReceiptStore(store_path)
        self._current_receipt: GovernanceReceipt | None = None
        self._events: list[dict[str, Any]] = []

    def v2_playbook_on_start(self, playbook: Any) -> None:
        playbook_content = ""
        try:
            playbook_path = getattr(playbook, "_file_name", "") or ""
            if playbook_path and Path(playbook_path).exists():
                playbook_content = Path(playbook_path).read_text(encoding="utf-8")
        except Exception:
            pass

        self._current_receipt = GovernanceReceipt(
            receipt_id=generate_receipt_id(),
            playbook_hash=hash_content(playbook_content),
            inventory_snapshot_hash="",     # populated in v2_playbook_on_play_start
            tier_decision="pending",
            tier_rationale="",
            triggered_by="",
            quorum_votes=[],
            execution_events=[],
            rollback_dag_hash=None,
            wall_clock_start=time.time(),
            wall_clock_end=None,
            execution_status="pending",
        )
        self._events = []

    def v2_playbook_on_play_start(self, play: Any) -> None:
        if self._current_receipt is None:
            return
        try:
            inventory_data = str(getattr(play, "_variable_manager", ""))
            self._current_receipt.inventory_snapshot_hash = hash_content(inventory_data)
        except Exception:
            pass

    def v2_runner_on_ok(self, result: Any) -> None:
        self._record_event("ok", result)

    def v2_runner_on_failed(self, result: Any, ignore_errors: bool = False) -> None:
        self._record_event("failed", result)

    def v2_runner_on_skipped(self, result: Any) -> None:
        self._record_event("skipped", result)

    def v2_runner_on_unreachable(self, result: Any) -> None:
        self._record_event("unreachable", result)

    def v2_playbook_on_stats(self, stats: Any) -> None:
        if self._current_receipt is None:
            return

        self._current_receipt.execution_events = self._events
        self._current_receipt.wall_clock_end = time.time()

        # Determine final execution status from stats
        try:
            failures = sum(stats.failures.values())
            unreachable = sum(stats.dark.values())
            if unreachable > 0:
                self._current_receipt.execution_status = "failed"
            elif failures > 0:
                self._current_receipt.execution_status = "failed"
            else:
                self._current_receipt.execution_status = "executed"
        except Exception:
            self._current_receipt.execution_status = "executed"

        self._store.append(self._current_receipt)
        self._current_receipt = None
        self._events = []

    def _record_event(self, event_type: str, result: Any) -> None:
        try:
            host = str(getattr(result, "_host", "unknown"))
            task_name = str(getattr(result._task, "get_name", lambda: "unknown")())
            task_args = {}
            try:
                task_args = dict(result._task.args or {})
                # Redact sensitive values
                for key in list(task_args.keys()):
                    if any(s in key.lower() for s in ("password", "token", "secret", "key")):
                        task_args[key] = "***REDACTED***"
            except Exception:
                pass

            self._events.append({
                "event": event_type,
                "host": host,
                "task": task_name,
                "timestamp": time.time(),
                "module": str(getattr(result._task, "action", "unknown")),
                "args_redacted": task_args,
            })
        except Exception:
            self._events.append({"event": event_type, "timestamp": time.time()})


# -------------------------------------------------------------------
# Standalone receipt generation (for testing / offline benchmark)
# -------------------------------------------------------------------

def create_mock_receipt(
    playbook_content: str,
    inventory_hosts: list[dict[str, Any]],
    tier_decision: str,
    tier_rationale: str,
    triggered_by: str,
    votes: list[GovernanceVote] | None = None,
    missed_by_baselines: list[str] | None = None,
) -> GovernanceReceipt:
    """
    Create a governance receipt for offline benchmark evaluation
    (without running Ansible).
    """
    return GovernanceReceipt(
        receipt_id=generate_receipt_id(),
        playbook_hash=hash_content(playbook_content),
        inventory_snapshot_hash=hash_content(json.dumps(inventory_hosts, sort_keys=True)),
        tier_decision=tier_decision,
        tier_rationale=tier_rationale,
        triggered_by=triggered_by,
        quorum_votes=votes or [],
        execution_events=[],
        rollback_dag_hash=None,
        wall_clock_start=time.time(),
        wall_clock_end=time.time(),
        execution_status="approved" if tier_decision in ("auto-approve", "canary") else "pending",
        missed_by_baselines=missed_by_baselines or [],
    )
