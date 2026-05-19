# Research Idea Report

**Direction**: Leveraging ACGS-Swarm constitutional governance capabilities with Ansible for enterprise production server and service design
**Generated**: 2026-05-19
**Ideas evaluated**: 12 generated → 5 passed first-pass filtering → 3 deep-validated → 3 recommended
**Reviewer**: Codex MCP (gpt-5.5, xhigh reasoning effort) + Claude Sonnet 4.6 synthesis

---

## Landscape Summary

The intersection of constitutional AI governance and infrastructure automation is largely unexplored. Three ecosystems are converging: **ACGS-Swarm** (orchestrator-free constitutional governance runtime with peer voting, AgentDNA enforcement, and signed settlement receipts), **Ansible** (the dominant agentless SSH automation framework with 5000+ modules, declarative YAML playbooks, and idempotent execution), and a wave of **enterprise LLM agent governance papers** (2025–2026) that have established risk-tiering, agent identity, and DAG-governed execution as viable research directions.

Existing papers cover LLM agent governance in back-office text tasks (POLARIS, AAAI 2026), dynamic risk tiering for generic agents (Dynamic Tiered AgentRunner, 2026), and agent identity in Kubernetes (ANS/DID, 2026)—but none bind constitutional governance to an **infrastructure execution plane**. Ansible's check/diff modes, ansible-lint, and OPA/Conftest provide static policy checking but lack multi-agent peer review, cryptographic execution receipts, or trust-weighted quorum enforcement. The security-smells-in-IaC literature (arXiv:2509.18761) has characterized the vulnerability landscape but not proposed governance-based mitigations.

The core opportunity is a **governed infrastructure execution layer**: constitutional governance that triggers *at the execution boundary*, not merely at the YAML authoring stage. This is where blast radius, agent authority, inventory-sensitive risk, and rollback validity intersect in ways that static lint tools cannot address.

Enterprise SRE teams today rely on manual code review, change advisory boards, and post-incident runbooks. An ACGS-Swarm constitutional layer could automate the governance decisions (approve/quorum-require/deny) that currently require human escalation chains—while generating auditable receipts that regulatory compliance demands.

---

## Recommended Ideas (ranked)

### Idea 1: GovernedAnsibleBench

- **Hypothesis**: The field lacks a concrete benchmark for governed infrastructure change decisions; building one will expose systematic failure modes in current LLM-generated IaC, policy-as-code tools, and constitutional governance systems, making future agent-governance claims falsifiable.
- **Minimum experiment**: Construct 100 enterprise-style Ansible change requests across 8 categories (Linux hardening, service deployment, cloud provisioning, secrets rotation, firewall rules, database maintenance, incident remediation, SLO-aware canary). For each: an inventory snapshot, playbook candidate(s), risk label, expected governance decision (auto-approve/quorum-required/human-required/deny), expected rollback DAG, and an executable local testbed. Evaluate ansible-lint, check mode, OPA/Conftest, GPT-4o reviewer, and ACGS-gated execution against expert SRE labels.
- **Expected outcome**: At least one category where static tools (lint/check/OPA) and constitutional governance systematically disagree with SRE experts, documenting a measurable gap in automated infra governance.
- **Novelty**: 9/10 — No benchmark exists for governed infra agent decisions. Closest: IaC security smell datasets (arXiv:2509.18761) focus on static vulnerability detection, not execution governance.
- **Feasibility**: No GPU required. Local VMs or containers (Docker Compose, Vagrant, Molecule) for testbeds. 2-3 weeks engineering for 100 tasks; 5-10 SRE annotators for labels (could use open-source maintainers).
- **Risk**: LOW-MEDIUM. The benchmark artifact is publishable regardless of which system performs best.
- **Contribution type**: Benchmark + diagnostic
- **Pilot result**: SKIPPED (no GPU needed; code-only validation viable)
- **Pilot design** (for manual execution): Build 10 representative tasks across 4 categories. Run ansible-lint, check mode, and a minimal ACGS stub against them. Measure agreement with manually labeled expected outcomes.
- **Reviewer's likely objection**: "Benchmarks are only accepted if they are broad, realistic, reusable, and not tailored to a specific system. The synthetic inventories and contrived policies may lack enterprise texture."
- **Counter**: Frame as a benchmark of **governed infra change decisions**, not bad YAML detection. Include realistic inventories, service criticality metadata, maintenance windows, secrets boundaries, executable testbeds, and multi-system evaluation. Negative results (tools disagree or fail) are first-class findings.
- **Target venue**: NeurIPS Datasets & Benchmarks, FSE, ICSE, SREcon
- **Why we should do this**: A benchmark unlocks all future work in this space. Without it, every governed-infra-agent paper makes unfalsifiable claims. GovernedAnsibleBench is the foundation that makes ideas 2 and 3 below rigorous and reproducible.

---

### Idea 2: Risk-Tiered Ansible Execution via Constitutional Governance

- **Hypothesis**: Most Ansible tasks can be reliably pre-classified into constitutional execution tiers (read-only / check-mode / canary / quorum-required / human-required / deny) based on module type, privilege level, blast radius, inventory group, secrets access, and reversibility—enabling automated safe execution without manual change advisory boards.
- **Minimum experiment**: Label 500–1,000 Ansible tasks from public playbooks (Ansible Galaxy roles + open-source infrastructure repos) using a published rubric tied to concrete controls. Train a lightweight classifier (no GPU: gradient boosting or rule-based system). Compare against expert SRE labels and, for a 50-task executable subset, inject failure scenarios and measure whether tier assignment prevents unauthorized execution.
- **Expected outcome**: >80% agreement with SRE experts on straightforward cases; identification of specific task categories (e.g., shell/command modules, unknown variables, multi-host patterns) where automated tiering is unreliable—informing the design of constitutional fallback rules.
- **Novelty**: 8/10 — Risk tiering for Ansible exists only as informal SRE practice (change windows, CABs). The Dynamic Tiered AgentRunner (arXiv:2605.10223) does risk tiering for back-office LLM agents but not infrastructure execution planes.
- **Feasibility**: No GPU. Python sklearn or rule-engine for classifier. Public playbooks from Ansible Galaxy for dataset. 3-4 weeks.
- **Risk**: MEDIUM. Expert label consistency may be low (making subjectivity *the finding*). A null result showing risk tiering is unreliable is still publishable if it identifies which features cause the breakdown.
- **Contribution type**: Empirical finding + new method
- **Pilot result**: SKIPPED (no GPU; code-only validation pending)
- **Pilot design** (for manual execution): Take 50 tasks from 5 public Ansible roles; apply the tiering rubric; compare classifications from 3 independent raters; compute Fleiss's kappa. If kappa > 0.7, tiering is reliable; if < 0.5, subjectivity is the finding.
- **Reviewer's likely objection**: "Risk classifiers for deployment/change management are not new; the novelty over policy-as-code (OPA) and change advisory board automation is unclear."
- **Counter**: Frame risk as **tiered execution consequence** (not vulnerability severity). The contribution is the rubric (tied to reversibility + blast radius + agent authority) and the calibration study. Show cross-org transfer experiments. If tiering breaks down, the paper documents *why* and *what constitutional fallback rules are needed*.
- **Target venue**: FSE, ICSE, USENIX ATC, SREcon
- **Why we should do this**: This is the method core that the GovernedAnsibleBench evaluates. It addresses the "who authorizes this change and at what tier?" question that every enterprise Ansible deployment currently answers with manual CABs.

---

### Idea 3: Replayable Governance Receipts for Ansible Runs

- **Hypothesis**: Cryptographically co-bound governance receipts (signed ACGS votes + policy decisions + playbook/inventory hashes + Ansible Runner job events) enable significantly more reliable infra audit outcomes than separately stored CI artifacts, in-toto attestations, or Ansible Runner artifacts alone.
- **Minimum experiment**: Build an Ansible callback plugin + ACGS wrapper that emits signed governance receipt bundles (JSONL, one record per task execution). Design an audit study: given a 30-task change history, can independent auditors detect (a) unauthorized executions, (b) stale-policy approvals, (c) log tampering, (d) missing quorum evidence, faster and more accurately with receipts vs. vanilla artifacts? Use 5-10 participants from SRE/DevSecOps communities.
- **Expected outcome**: Receipt-based audit detects tampering/unauthorized-execution scenarios with higher recall and lower time-to-detection than reviewing raw CI logs + Ansible Runner artifacts.
- **Novelty**: 7/10 — in-toto/SLSA cover supply chain provenance; ACGS governance receipts extend this to **decision-level evidence**: who voted, under what constitutional rule, on what playbook version, against what inventory. The gap is the governance/execution mismatch that attestations miss.
- **Feasibility**: No GPU. Python plugin for Ansible callback. SQLite or JSONL store. 2-3 weeks for the plugin; 1-2 weeks for the audit user study.
- **Risk**: LOW-MEDIUM. The plugin is straightforward to build; the novelty challenge is differentiating from in-toto/Sigstore. Must explicitly benchmark against both.
- **Contribution type**: System design + diagnostic
- **Pilot result**: SKIPPED (no GPU needed; code-only validation viable)
- **Pilot design** (for manual execution): Build the callback plugin for 10 representative tasks; generate receipt bundles; attempt to detect injected anomalies (unauthorized execution, missing quorum approval) using only the receipts vs. raw Runner artifacts.
- **Reviewer's likely objection**: "Tamper-evident provenance already exists: in-toto, SLSA, Sigstore, audit logs. This is an implementation note, not a paper."
- **Counter**: Scope carefully: not "replayable infrastructure" but **"replayable governance decisions bound to execution evidence."** The claim is that existing attestation systems record *what changed*, not *who authorized it under which constitutional rule against which risk tier at what quorum threshold.* Show the gap with a comparative study on audit tasks where in-toto passes but ACGS receipts detect a governance mismatch.
- **Target venue**: USENIX ATC, HotOS, SREcon, ACM CCS workshops (security track)
- **Why we should do this**: Clean systems contribution with high enterprise relevance. Regulatory compliance (SOX, ISO27001, SOC2) demands exactly this type of audit trail. Low compute, actionable, and differentiates clearly from existing provenance work once scoped correctly.

---

## Eliminated Ideas (for reference)

| Idea | Reason eliminated |
|------|-------------------|
| Constitutional Ansible Runner Gate (#1) | Strong as a *substrate* but not standalone paper; collapses into "policy gate + agents" without #3 or #12 foundation. Merge into GovernedAnsibleBench evaluation. |
| Governed LLM-to-Ansible Pipeline (#4) | LLM-to-IaC safety space is crowded. The execution boundary framing is valid but needs a distinct benchmark (→ #12) and risk-tiering method (→ #3) to avoid "generate-then-lint" framing. |
| Agent Identity for Infrastructure Operators (#5) | ANS/DID paper (arXiv:2604.26997) already covers the Kubernetes identity layer. Needs differentiation. Viable as a subsection of #3. |
| Settlement-Driven Rollback Protocol (#7) | High systems engineering complexity; requires full rollback DAG design. HIGH risk. Viable as future work extension of #1/#3. |
| Spectral Trust Quorums for Infra Agents (#8) | Interesting but primarily theoretical; needs large-scale agent simulation. Follow-on work after #12 establishes baselines. |
| Privacy-Preserving Incident Broadcasts (#9) | DP/zk-SNARK protocol is from ACGS-Swarm's advanced research module; needs DP theory expertise. HIGH complexity and risk for the timeline. |
| Orchestrator-Free Ansible Mesh (#10) | Compelling but high systems engineering (multi-site, network partitions). Best as a full systems paper (EuroSys/USENIX ATC) after establishing baseline with #2 and #3. |
| SLO-Aware Constitutional Canaries (#11) | Good production engineering idea; lower novelty as a research paper. Better as an engineering blog post or conference talk. |

---

## Pilot Experiment Results

*No GPU available in this environment. All pilots flagged for manual execution.*

| Idea | GPU | Time | Key Metric | Signal |
|------|-----|------|------------|--------|
| GovernedAnsibleBench (#12) | N/A | SKIPPED | 10-task pilot: label agreement rate | Needs manual pilot (no GPU required) |
| Risk-Tiered Execution (#3) | N/A | SKIPPED | Fleiss's kappa on 50-task label study | Needs manual pilot (no GPU required) |
| Governance Receipts (#2) | N/A | SKIPPED | Audit recall/precision vs. raw artifacts | Needs manual pilot (no GPU required) |

**Code-only validation status**:
- [x] ACGS-Swarm `constitutional-swarm` package exists on PyPI and installs with Python 3.11+
- [x] Ansible Runner callback plugin architecture confirmed (supports custom callbacks via `callback_plugins`)
- [x] Ansible check/diff mode confirmed for dry-run comparison baseline
- [ ] 10-task pilot for GovernedAnsibleBench — awaiting manual execution
- [ ] 50-task labeling study for risk-tiering — awaiting manual execution

---

## Suggested Execution Order

1. **Start with GovernedAnsibleBench** — build the 100-task corpus and executable testbeds (3-4 weeks). This unlocks rigorous evaluation for all other ideas and is publishable as a standalone benchmark paper.

2. **Run Risk-Tiered Execution study in parallel** — labeling study can begin with 50 public Ansible Galaxy tasks immediately. Fleiss's kappa result (positive or negative) shapes the constitutional tier design.

3. **Build Governance Receipts plugin** after the first two establish baselines — 2 weeks to implement the callback plugin + audit study. Position as the "auditability story" that ties the other two together.

4. **Merge into a systems paper** after 3 ideas produce results — frame as: *GovernedAnsibleBench (dataset) + Risk-Tiered Execution (method) + Governance Receipts (audit story) = ACGS-Governed-Ansible: A Constitutional Execution Framework for Enterprise Infrastructure Automation.*

---

## Next Steps

- [ ] Implement 10-task GovernedAnsibleBench pilot: select tasks from Ansible Galaxy, build Docker testbeds, label with rubric
- [ ] Set up `constitutional-swarm` + ansible-runner integration stub (2-3 days)
- [ ] Define the 6-tier risk rubric (linked to reversibility, blast radius, privilege, secrets)
- [ ] Recruit 3 SRE raters for inter-rater agreement study
- [ ] Build the Ansible callback plugin for governance receipt emission
- [ ] Write comparison against ansible-lint, check mode, OPA on the 10 pilot tasks
- [ ] If results positive: scale to 100 tasks and submit GovernedAnsibleBench to NeurIPS D&B or FSE

---

## Implementation Architecture (for Stage 2)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   ACGS-Governed-Ansible Stack                       │
├─────────────────────────────────────────────────────────────────────┤
│  LLM / SRE Operator                                                 │
│       │ proposes playbook                                           │
│       ▼                                                             │
│  ┌──────────────┐                                                   │
│  │ AgentDNA     │ ← Local constitutional check (syntax, policy,     │
│  │ (ACGS-Swarm) │   blast radius estimate, tier assignment)         │
│  └──────┬───────┘                                                   │
│         │ if tier ≥ QUORUM_REQUIRED                                 │
│         ▼                                                           │
│  ┌──────────────────┐                                               │
│  │ ConstitutionalMesh│ ← Peer agent votes + quorum settlement       │
│  │ (ACGS-Swarm)      │   (signed votes, SpectralSphere trust)       │
│  └──────┬────────────┘                                              │
│         │ settlement reached                                        │
│         ▼                                                           │
│  ┌──────────────────┐                                               │
│  │ Risk-Tier Gate   │ ← Execute: auto / canary / human-gate / deny │
│  │                  │   + Ansible check mode for dry run            │
│  └──────┬───────────┘                                               │
│         │ approved                                                  │
│         ▼                                                           │
│  ┌──────────────────┐                                               │
│  │ ansible-runner   │ ← Actual execution via SSH                   │
│  │ + callback plugin│   job_events streamed to receipt store        │
│  └──────┬───────────┘                                               │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────────────────────────┐                       │
│  │ Governance Receipt Bundle (JSONL/SQLite) │                       │
│  │  - Playbook hash + inventory snapshot    │                       │
│  │  - AgentDNA tier decision + rationale    │                       │
│  │  - Signed mesh votes + quorum evidence   │                       │
│  │  - Ansible Runner job_events log         │                       │
│  │  - Rollback DAG (if required)            │                       │
│  └──────────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Baseline Comparison Matrix

| Capability | ansible-lint | check/diff mode | OPA/Conftest | ACGS-Governed-Ansible |
|------------|:-----------:|:---------------:|:------------:|:---------------------:|
| Static YAML analysis | ✅ | ❌ | ✅ | ✅ |
| Dry-run execution | ❌ | ✅ | ❌ | ✅ |
| Blast-radius estimation | ❌ | ❌ | Partial | ✅ |
| Peer review / quorum | ❌ | ❌ | ❌ | ✅ |
| Agent authority check | ❌ | ❌ | Partial | ✅ |
| Replayable audit receipt | ❌ | ❌ | ❌ | ✅ |
| Trust dynamics | ❌ | ❌ | ❌ | ✅ |
| Enterprise CAB replacement | ❌ | ❌ | Partial | ✅ |

