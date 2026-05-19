# Research Pipeline Execution Report

**Pipeline**: /research-pipeline  
**Direction**: Leverage ACGS-Swarm capabilities with Ansible for enterprise production server/service design  
**Result**: GovernedAnsibleBench — 6/10 FSE/ICSE tools track (borderline accept)

---

## Pipeline Execution Summary

### Stages Completed

| Stage | Output | Status |
|-------|--------|--------|
| Literature survey | `idea-stage/lit_survey_notes.md` | ✅ |
| Idea generation (12 ideas via Codex) | — | ✅ |
| Idea filtering + ranking | `idea-stage/IDEA_REPORT.md` | ✅ |
| Gate 1: Idea selection | GovernedAnsibleBench selected | ✅ (auto) |
| Core implementation | classifier, receipts, baselines | ✅ |
| Unit tests (6 tier classifier tests) | 6/6 pass | ✅ |
| Auto-review Round 1 | **4/10** — stub baselines, 5 tasks | ✅ |
| Minimum fixes (real baselines, ablation) | 5-task full eval with ablation | ✅ |
| Auto-review Round 2 | **5/10** — needs corpus expansion | ✅ |
| Task corpus expansion | 100 tasks, 8 categories | ✅ |
| Full evaluation | 88% ACGS, 76% OPA, 36% lint | ✅ |
| Auto-review Round 3 | **6/10** — borderline accept | ✅ |
| NARRATIVE_REPORT.md | `NARRATIVE_REPORT.md` | ✅ |

### Review Score Progression

```
Round 1:  4/10  (stub baselines, 5 tasks, no ablation)
Round 2:  5/10  (real baselines, ablation, still 5 tasks)
Round 3:  6/10  (100 tasks, per-category ablation, honest OPA framing)
```

### Compute Used

- **GPU hours**: 0 (all experiments are code-only, no ML training)
- **LLM calls**: 3 × Codex MCP review rounds
- **Tasks evaluated**: 100
- **Baseline implementations**: 4 (ansible-lint, check-mode, OPA, ACGS) + 4 ablation variants

---

## Key Research Findings

1. **Context is the dominant feature** (29pp drop without full context): Inventory-context-aware classification is not just beneficial, it's the primary driver of governance accuracy.

2. **Inventory context adds 18pp** beyond playbook content alone: Environment (prod vs dev), criticality (tier1 vs tier3), and maintenance windows are necessary inputs for correct tier decisions.

3. **Default Ansible tools fail** (36-34% accuracy): ansible-lint and check-mode analyze syntax, not governance semantics — they cannot make production authorization decisions.

4. **OPA is a viable policy backend** (76% with context, vs 88% ACGS): The gap comes from missing compound conditional rules (regulatory scope + irreversibility → T4), not OPA's fundamental limitations. OPA with a full constitutional Rego policy would likely match ACGS.

5. **Blast radius matters incrementally** (4pp drop without it): Useful but not dominant on a 100-task corpus.

6. **Governance receipts enable audit anomaly detection**: 3/3 injected anomalies detected — unauthorized execution, missing quorum evidence, and post-approval tampering — none detectable via raw Ansible artifacts alone.

---

## Files Produced

```
.
├── NARRATIVE_REPORT.md                   ← Research narrative (this run)
├── PIPELINE_REPORT.md                    ← This file
├── idea-stage/
│   ├── lit_survey_notes.md              ← ACGS-Swarm + Ansible literature survey
│   └── IDEA_REPORT.md                   ← 12 ideas → 3 recommended → 1 selected
├── review-stage/
│   └── EXPERIMENT_SUMMARY.md            ← Summary for review loop
└── governed-ansible-bench/
    ├── README.md
    ├── docs/
    │   ├── task_schema.json             ← JSON Schema for benchmark tasks
    │   └── labeling_rubric.md           ← 5-tier annotator rubric with decision tree
    ├── evaluation/
    │   ├── risk_tier_classifier.py      ← Constitutional 5-tier classifier (88%, all 6 tests pass)
    │   ├── generate_tasks.py            ← 100-task corpus generator
    │   ├── run_pilot.py                 ← Pilot harness (5 tasks)
    │   ├── run_full_eval.py             ← Full evaluation with ablation + context sensitivity
    │   └── audit_study.py              ← Audit anomaly detection (3/3 detected)
    ├── baselines/
    │   ├── real_baselines.py            ← Real ansible-lint, check-mode, OPA, ACGS baselines
    │   └── opa/ansible_governance.rego  ← OPA Rego policy
    ├── receipts/
    │   └── governance_receipt_emitter.py ← Ansible callback plugin + JSONL receipt store
    ├── tasks/                            ← 100 task JSON files (8 categories)
    └── results/
        ├── pilot_results.json
        └── full_eval_results.json       ← 100-task results with ablation
```

---

## Recommended Next Steps (for submission)

### Before Submission (P0)
1. Add 3 independent SRE annotators → compute Fleiss's kappa (target ≥ 0.7)
2. Implement `OPA-rubric-complete` baseline (full constitutional Rego policy) — closes the fairness gap the reviewer identified
3. Add per-category F1 table and confusion matrix to results

### Before Submission (P1)
4. Expand audit study (A2: stale policy, A3: log tamper, A6: missing job event)
5. Add 20+ SLO-sensitive tasks where removing SLO context causes tier degradation
6. Human participant study: time-to-detect 5 anomaly types with receipts vs without

### Future Work
7. Real ACGS ConstitutionalMesh peer voting integration (multi-agent quorum)
8. Cross-organization policy generalization study
9. Live Ansible Runner callback plugin evaluation with real playbooks

---

**Final assessment**: GovernedAnsibleBench is a viable systems/tools contribution for FSE/ICSE with the 6/10 borderline-accept score. The core value is the benchmark corpus + constitutional rubric + governance receipt mechanism, not the Python rule engine itself. The paper should be positioned as a tools track contribution, not a machine learning contribution.
