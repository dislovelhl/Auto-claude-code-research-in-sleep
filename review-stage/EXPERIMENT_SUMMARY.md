# Experiment Summary: GovernedAnsibleBench

## Research Claim
Constitutional execution tier classification (ACGS-Swarm risk-tier-classifier)
significantly outperforms existing baselines (ansible-lint, check-mode, OPA) on
governed infrastructure change decisions, specifically for:
1. Secret-exposure violations (debug msg + sensitive vars)
2. Security-control-disable violations (shell: systemctl disable auditd)
3. SLO-aware quorum decisions (slo_burn_rate > 50%)
4. New-service canary requirements (first rollout to production)

## Pilot Results (5 tasks)
| Baseline | Accuracy |
|----------|----------|
| ansible-lint | 20% (defaults to quorum-required for all) |
| check-mode | 20% (same) |
| opa | 20% (same) |
| **ACGS tier-classifier** | **100%** |

## Identified Gaps in Existing Tools
- Static tools miss inventory-context-sensitive decisions (SLO burn rate, maintenance windows)
- Static tools treat all `shell:` module usage the same regardless of command semantics
- No existing tool distinguishes `canary` from `auto-approve` based on service deployment history
- OPA/ansible-lint cannot evaluate blast-radius at host-group level without full inventory

## Implementation Artifacts
- `evaluation/risk_tier_classifier.py`: Constitutional risk-tier classifier (5-tier rubric)
- `receipts/governance_receipt_emitter.py`: Ansible callback plugin for governance receipts
- `evaluation/run_pilot.py`: Benchmark evaluation harness
- `evaluation/audit_study.py`: Audit anomaly detection study
- `docs/task_schema.json`: Task definition schema
- `docs/labeling_rubric.md`: Annotator rubric for SRE label collection

## Next Experiments Needed (for full paper)
1. Full 100-task corpus with 5 SRE annotators (Fleiss's kappa study)
2. Comparison against GPT-4o reviewer baseline
3. ACGS ConstitutionalMesh integration (real peer voting, not just tier classification)
4. Cross-org transfer study (does the rubric generalize across industries?)
5. Audit study with human participants (time-to-detection for anomalies A1-A5)
