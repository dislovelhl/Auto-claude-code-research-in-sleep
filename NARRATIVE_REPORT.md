# GovernedAnsibleBench: A Benchmark for Context-Aware Execution-Tier Governance of Ansible Infrastructure Changes

**Research Direction**: ACGS-Swarm constitutional governance + Ansible for enterprise production server/service design
**Chosen Idea**: GovernedAnsibleBench (#1 from idea generation)
**Status**: Borderline Accept (6/10, FSE/ICSE tools track)

---

## Problem Statement

Enterprise infrastructure automation with Ansible lacks a constitutional governance layer that enforces context-aware execution authorization. Existing tools (ansible-lint, Ansible check/diff mode, OPA/Conftest) analyze playbook syntax or policy rules but **cannot make execution-tier decisions that depend on inventory context**: which environment (production vs staging), service criticality (tier1 vs tier3), SLO error budget burn rate, maintenance windows, blast radius, and regulatory scope.

This gap means enterprise SRE teams rely on manual change advisory boards (CABs) and human escalation chains for decisions that could be automated with the right governance model—while still lacking a replayable audit trail that binds authorization decisions to execution evidence.

**Core Claim**: Execution-tier governance for Ansible playbooks requires inventory-context-aware classification unavailable in default Ansible tooling. A constitutional tiering rubric paired with replayable governance receipts provides a reusable, automatable governance layer that reduces manual CAB overhead while improving audit reliability.

---

## Method Summary

### 1. Constitutional Risk-Tier Classifier (`risk_tier_classifier.py`)

A rule-based classifier implementing the 5-tier constitutional rubric:
- **T5 deny**: Absolute prohibitions (secret exposure in debug, security control disable, unsafe chmod, DB destruction)
- **T4 human-required**: Irreversible changes on production tier1 with regulatory scope or datacenter blast radius
- **T3 quorum-required**: High blast radius, secrets on production, elevated privilege on production, SLO burn >50%
- **T2 canary**: First rollout of new service or routing modification to production
- **T1 auto-approve**: Staging/development hosts, single-host, fully reversible, no secrets

Decision tree is top-down; highest-severity rule wins.

### 2. Governance Receipt Emitter (`receipts/governance_receipt_emitter.py`)

Ansible callback plugin that emits JSONL governance receipt bundles per execution:
- Playbook SHA-256 hash + inventory snapshot hash
- Tier decision + rationale + triggered rule
- Constitutional vote records (GovernanceVote with agent_id, decision, rationale)
- Ansible Runner job_events (task-level execution evidence, secrets redacted)
- Execution status (pending/approved/denied/executed/failed)

### 3. GovernedAnsibleBench Corpus

100 tasks across 8 categories (12-13 tasks each):
- linux_hardening, service_deploy, secrets_rotation, firewall_rules
- database_maintenance, incident_remediation, canary_deploy, cloud_provisioning

Each task: playbook content + inventory metadata (environment, criticality, SLO burn rate, regulatory scope, maintenance window) + expected tier + tier rationale + common_mistakes (what static tools miss).

Tier distribution: auto-approve (35), canary (18), quorum-required (32), human-required (8), deny (7)

---

## Key Quantitative Results

### Main Comparison (100 tasks, 8 categories)

| Baseline | Accuracy | Macro-F1 |
|----------|----------|----------|
| ansible-lint | 36% | 10.7% |
| check-mode | 34% | 12.1% |
| OPA (with inventory context) | 76% | 57.6% |
| **ACGS tier-classifier (full)** | **88%** | **87.5%** |

### Ablation Study

| Configuration | Accuracy | Macro-F1 | Drop |
|---------------|----------|----------|------|
| Full (all context) | 88% | 87.5% | — |
| No inventory context | 70% | 59.2% | -18pp |
| No context at all | 59% | 46.6% | -29pp |
| No SLO context | 88% | 87.5% | 0pp* |
| No blast radius | 84% | 79.6% | -4pp |

*SLO effect under-represented in current 100-task corpus — needs more SLO-burning + conflicting-tier tasks.

### Context Sensitivity

Same playbook under different inventory contexts:
- Dev low criticality → canary (new service on dev, safe)
- Prod tier1 SLO burn 80% → **quorum-required** (escalation)
- Prod maintenance window → canary (in-window, but still needs canary for new service)

### Audit Study (3 anomaly types)

All 3 injected anomalies detected via governance receipts:
- A1: deny-tier execution (unauthorized execution) — **detected**
- A4: quorum-required with no votes (missing quorum evidence) — **detected**
- A5: playbook hash mismatch after approval (tampering) — **detected**

These anomalies were NOT detectable via raw Ansible Runner artifacts or in-toto attestations alone.

---

## Figure/Table Inventory

Figures needed (for paper):
1. **Architecture diagram**: LLM/SRE → AgentDNA → ConstitutionalMesh → Risk-Tier Gate → ansible-runner → Receipt Store
2. **Confusion matrix**: ACGS vs OPA on 100 tasks (5×5 tier matrix)
3. **Ablation bar chart**: Accuracy/macro-F1 per ablation configuration
4. **Context sensitivity heatmap**: Same playbook, 3 inventory variants, 5 tier rows

Tables present in code:
- Table 1: Main comparison (accuracy + macro-F1 per baseline)
- Table 2: Ablation study
- Table 3: Per-category F1 scores
- Table 4: Audit anomaly detection comparison (receipts vs raw artifacts)

---

## Limitations

1. **Label bias**: Same authors wrote rubric, tasks, and classifier — need independent SRE annotators and Fleiss's kappa study
2. **OPA parity gap**: The 12pp OPA-ACGS gap may close if OPA Rego policy includes regulatory scope + irreversibility compound condition
3. **SLO under-coverage**: Current 100-task corpus lacks sufficient SLO-burning + safe-change combinations to demonstrate SLO feature value
4. **No real ConstitutionalMesh quorum**: The classifier implements the tier decision logic; actual peer voting via ACGS ConstitutionalMesh is future work
5. **No human user study**: Audit anomaly detection is automated; human participants study (time-to-detection, recall vs raw artifacts) is needed for a full paper
6. **No cross-organization transfer**: All tasks use a single organizational policy; generalizability across industries is unverified

---

## Remaining Follow-Up Items

- [ ] Add independent SRE annotators (minimum 3) for Fleiss's kappa study
- [ ] Implement OPA-rubric-complete baseline (full constitutional Rego policy)
- [ ] Expand audit anomaly study (A2: stale policy, A3: inventory hash mismatch, A5: full tampering)
- [ ] Add 20+ SLO-context-sensitive tasks to demonstrate SLO feature value
- [ ] Implement real ACGS ConstitutionalMesh peer voting integration
- [ ] Human participant audit study (compare receipts vs raw artifacts for 5 anomaly types)
- [ ] Per-category confusion matrix and F1 breakdown
