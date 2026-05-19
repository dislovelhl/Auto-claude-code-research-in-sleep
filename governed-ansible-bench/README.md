# GovernedAnsibleBench

**A benchmark for governed infrastructure change decisions with ACGS-Swarm + Ansible**

## Overview

GovernedAnsibleBench is a benchmark of 100 enterprise-style Ansible change requests with:
- Inventory snapshots (service criticality, maintenance windows, secrets boundaries)
- Playbook candidates (correct, vulnerable, overprivileged, non-idempotent variants)
- Risk labels: `auto-approve | canary | quorum-required | human-required | deny`
- Expected governance decision with rationale
- Expected rollback DAG (for risky changes)
- Executable local testbeds (Docker Compose / Molecule)

## Research Hypothesis

> Peer constitutional review (ACGS-Swarm ConstitutionalMesh) catches materially more unsafe infrastructure changes than `ansible-lint`, check/diff mode, OPA/Conftest, or LLM reviewer alone — specifically for blast-radius, agent-authority, and production-context violations that static tools miss.

## Task Categories (8 × 12-13 tasks = 100 total)

| Category | Tasks | Key Governance Challenges |
|----------|-------|--------------------------|
| Linux Hardening | 12 | Privilege escalation, kernel params, sshd config |
| Service Deployment | 13 | Blast radius, rollback, health checks |
| Cloud Provisioning | 12 | Cost blast, region scope, IAM overprivilege |
| Secrets Rotation | 13 | Exposure in logs, race conditions, vault access |
| Firewall Rules | 12 | Overly permissive rules, production exposure |
| Database Maintenance | 13 | Data loss risk, downtime, backup verification |
| Incident Remediation | 13 | Time pressure vs safety, SLO-awareness |
| Canary Deployment | 12 | Blast radius, rollback trigger, canary criteria |

## Baseline Systems Evaluated

1. **ansible-lint** — static YAML analysis
2. **Ansible check/diff mode** — dry-run execution
3. **OPA/Conftest** — policy-as-code enforcement
4. **LLM reviewer** — GPT-4o playbook review
5. **ACGS-Governed-Ansible** — ConstitutionalMesh + risk-tier gate + receipts

## Evaluation Metrics

- **Precision/Recall**: governance decision vs. SRE expert labels
- **F1 per tier**: auto-approve / canary / quorum-required / deny
- **Fleiss's kappa**: inter-rater agreement among SRE annotators
- **Time-to-detection**: audit task completion time (receipts vs. raw artifacts)
- **Cross-tier confusion**: which systems over-approve or over-block

## Quick Start

```bash
# Install dependencies
pip install ansible ansible-runner constitutional-swarm pytest

# Run 10-task pilot
python evaluation/run_pilot.py --tasks tasks/linux_hardening/ --baselines lint,checkmode

# Full evaluation
python evaluation/run_eval.py --all-tasks --all-baselines --output results/
```

## Project Structure

```
governed-ansible-bench/
├── tasks/                    # 100 benchmark tasks (8 categories)
│   ├── linux_hardening/
│   ├── service_deploy/
│   ├── cloud_provisioning/
│   ├── secrets_rotation/
│   ├── firewall_rules/
│   ├── database_maintenance/
│   ├── incident_remediation/
│   └── canary_deploy/
├── testbeds/                 # Executable Docker/Molecule environments
│   ├── docker/
│   └── molecule/
├── baselines/                # Baseline system implementations
│   ├── ansible_lint/
│   ├── check_mode/
│   ├── opa/
│   └── llm_reviewer/
├── receipts/                 # ACGS governance receipt schema + examples
├── evaluation/               # Evaluation harness + metrics
└── docs/                     # Task schema, labeling rubric, annotation guide
```
