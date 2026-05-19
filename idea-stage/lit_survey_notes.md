# Literature Survey: ACGS-Swarm + Ansible Enterprise Production Systems
Date: 2026-05-19

## Sources: Web search (arXiv API rate-limited, used direct URL fetches)

## Key Frameworks Surveyed

### 1. ACGS-Swarm (dislovelhl/Acgs-Swarm, 2025-2026) ⚠️ UNVERIFIED via arXiv/DOI
- **What**: Constitutional governance runtime for multi-agent systems
- **Core**: AgentDNA (local enforcement) → DAGCompiler/SwarmExecutor → ConstitutionalMesh (peer votes) → SettlementStore → governance receipts
- **Advanced**: SpectralSphere trust dynamics, DP broadcast (ε,δ)-DP + zk-SNARKs (MACI)
- **Gaps**: No Ansible integration, no infra execution plane, no enterprise deployment guide
- **Source**: github.com/dislovelhl/Acgs-Swarm (direct fetch)

### 2. Ansible (ansible/ansible) ⚠️ UNVERIFIED via arXiv/DOI
- **What**: Agentless IT automation (SSH-based), config mgmt, deployment, orchestration
- **Design**: Agentless, YAML playbooks, declarative, idempotent
- **Gaps**: No native AI/LLM governance, no dynamic risk tiering, no peer review of changes

### 3. Swarms Framework (kyegomez/swarms) ⚠️ UNVERIFIED via arXiv/DOI
- **What**: Enterprise-grade multi-agent orchestration
- **Core**: Sequential, Concurrent, Hierarchical, DAG, MoA, GroupChat, ForestSwarm architectures
- **Production**: 99.9%+ uptime, backward compat with LangChain/AutoGen/CrewAI, MCP support

## Key Papers Found

### P1: Dynamic Tiered AgentRunner (Pan & Hou, arXiv:2605.10223, 2026) ⚠️ UNVERIFIED
- **Problem**: LLM agent frameworks prioritize autonomy but lack governability for enterprise
- **Method**: 3 mechanisms: Risk-Adaptive Tiering + Separation of Powers + Verifier-Recovery loop
- **Result**: Pareto-optimal safety/efficiency tradeoff; distilled from production SaaS platform
- **Relevance**: Direct blueprint for enterprise ACGS-Swarm + Ansible integration

### P2: Agent Name Service (Mittal & De La Cruz, arXiv:2604.26997, 2026) ⚠️ UNVERIFIED
- **Problem**: Lack of agent discovery, authentication, capability proof, policy enforcement
- **Method**: DNS-inspired trust layer: DIDs + VCs + OPA + Kubernetes CRDs + service mesh
- **Result**: Sub-10ms response in 50-agent demo, full deployment success
- **Relevance**: Identity layer for ACGS-Swarm agents executing Ansible tasks in K8s

### P3: POLARIS (Moslemi et al., arXiv:2601.11816, AAAI 2026) ⚠️ UNVERIFIED
- **Problem**: Enterprise back-office workflows need auditable, policy-aligned, predictable agents
- **Method**: Typed plan synthesis (DAG) + rubric-guided selection + validator-gated execution + policy guardrails
- **Result**: 0.81 F1 on SROIE; 0.95-1.00 precision for anomaly routing with audit trails
- **Relevance**: Closest existing work to governed Ansible execution via agentic DAGs

### P4: E2E-REME (Zhang et al., FSE'26, arXiv:2604.xxx) ⚠️ UNVERIFIED
- **Problem**: LLM-based microservices auto-remediation translates text → code without experience
- **Method**: Experience-simulation reinforcement fine-tuning
- **Result**: Accepted at FSE'26
- **Relevance**: Auto-remediation with Ansible playbooks as execution actions

### P5: AOI - Autonomous Cloud Diagnosis (Yang et al., 2026) ⚠️ UNVERIFIED
- **Problem**: LLM SRE agents face restricted data access, unsafe action execution, no failure learning
- **Method**: Failure trajectory learning → training signals for autonomous cloud diagnosis
- **Relevance**: Foundation for ACGS-Swarm governed cloud ops with Ansible execution

### P6: Security Smells in IaC (War et al., arXiv:2509.18761, 2025) ⚠️ UNVERIFIED
- **Problem**: Security vulnerabilities in Ansible/Terraform IaC at scale
- **Method**: Extended taxonomy of security smells in IaC
- **Relevance**: Validates need for constitutional enforcement on Ansible playbook generation

## Literature Landscape

### Sub-Directions
1. **Governed agentic execution** (POLARIS, Dynamic Tiered AgentRunner) — active area, mostly back-office
2. **Agent identity & trust** (ANS) — Kubernetes-native, VC/DID based
3. **IaC security** — security smells in Ansible/Terraform
4. **LLM-driven remediation** (E2E-REME, AOI) — cloud ops, microservices
5. **Constitutional governance runtimes** (ACGS-Swarm) — peer-validated, orchestrator-free

### Open Gaps (Potential Research Directions)
1. **Constitutional governance for IaC execution** — No paper combines ACGS-Swarm (peer-voted governance) with Ansible playbook execution
2. **Risk-tiered infrastructure automation** — Dynamic Tiered AgentRunner applied to infra changes (not back-office text tasks)
3. **Agent identity for infra operators** — ANS/DID for Ansible-executing agents at enterprise scale  
4. **Replayable audit trails for infra changes** — governance receipts bound to Ansible run logs
5. **Operator-free multi-agent infra management** — orchestrator-free infra ops with constitutional enforcement + Ansible

### Consensus
- Enterprise AI agents need: governability + auditability + policy alignment (consensus)
- Separation of concerns: proposal / review / execution / verification (consensus in P1, P3)
- Peer validation is novel but unexplored for infra automation
- Ansible's agentless design is complementary to agentic governance (no bootstrapping conflict)

### Disagreements
- Centralized orchestrator vs. orchestrator-free (POLARIS uses planner; ACGS-Swarm is orchestrator-free)
- Risk tiering approach (P1 dynamic tiering vs P3 type-checking)
