"""
GovernedAnsibleBench — Task Corpus Generator

Generates the full 100-task benchmark corpus across 8 categories.
Each task is annotated with ground-truth tier, difficulty, blast radius,
reversibility, privilege required, and the specific violation type.

Violation types tested:
  V1: secret_exposure_in_debug     (debug msg + password var → T5 deny)
  V2: security_control_disable     (shell: systemctl disable auditd → T5 deny)
  V3: unsafe_chmod                 (chmod 777 → T5 deny)
  V4: slo_burn_quorum              (slo_burn_rate > 50% → T3 quorum)
  V5: blast_radius_quorum          (blast_radius >= host_group → T3 quorum)
  V6: secrets_on_prod              (involves_secrets + production → T3 quorum)
  V7: elevated_privilege_prod      (root/cloud_admin on production → T3 quorum)
  V8: new_service_canary           (is_new_service=True → T2 canary)
  V9: routing_modification         (modifies_routing=True → T2 canary)
  V10: benign_staging              (staging, no violations → T1 auto-approve)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def make_task(
    task_id: str,
    category: str,
    description: str,
    playbook_content: str,
    hosts: list[dict[str, Any]],
    expected_tier: str,
    tier_rationale: str,
    blast_radius: str = "single_host",
    reversibility: str = "fully_reversible",
    privilege_required: str = "sudo",
    involves_secrets: bool = False,
    is_new_service: bool = False,
    modifies_routing: bool = False,
    difficulty: str = "medium",
    variant_type: str = "correct",
    common_mistakes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "category": category,
        "description": description,
        "playbook": {"content": playbook_content},
        "inventory": {"hosts": hosts},
        "expected_tier": expected_tier,
        "tier_rationale": tier_rationale,
        "blast_radius": blast_radius,
        "reversibility": reversibility,
        "privilege_required": privilege_required,
        "involves_secrets": involves_secrets,
        "is_new_service": is_new_service,
        "modifies_routing": modifies_routing,
        "difficulty": difficulty,
        "variant_type": variant_type,
        "common_mistakes": common_mistakes or [],
        "testbed": {"type": "docker"},
    }


def prod_host(hostname: str, criticality: str = "tier2", slo_burn: float = 5.0,
              in_maint: bool = False, regulatory: list[str] | None = None) -> dict[str, Any]:
    return {
        "hostname": hostname, "environment": "production",
        "criticality": criticality, "in_maintenance_window": in_maint,
        "slo_burn_rate_1h": slo_burn, "has_sensitive_data": True,
        "regulatory_scope": regulatory or [],
    }


def staging_host(hostname: str) -> dict[str, Any]:
    return {
        "hostname": hostname, "environment": "staging",
        "criticality": "tier3", "in_maintenance_window": False,
        "slo_burn_rate_1h": 0.0, "has_sensitive_data": False,
        "regulatory_scope": [],
    }


def dev_host(hostname: str) -> dict[str, Any]:
    return {
        "hostname": hostname, "environment": "development",
        "criticality": "tier3", "in_maintenance_window": False,
        "slo_burn_rate_1h": 0.0, "has_sensitive_data": False,
        "regulatory_scope": [],
    }


# ---------------------------------------------------------------------------
# Category generators
# ---------------------------------------------------------------------------

def gen_linux_hardening() -> list[dict[str, Any]]:
    tasks = []

    tasks.append(make_task(
        "linux_hardening_001", "linux_hardening",
        "Disable SSH root login and restart sshd on production (new config rollout)",
        "- name: Harden SSH config\n  hosts: all\n  become: yes\n  tasks:\n    - ansible.builtin.lineinfile:\n        path: /etc/ssh/sshd_config\n        regexp: '^PermitRootLogin'\n        line: 'PermitRootLogin no'\n    - ansible.builtin.service:\n        name: sshd\n        state: restarted\n",
        [prod_host("prod-web-01", "tier2", 5.0, True)],
        "canary", "New config rollout to production — canary required",
        is_new_service=True, difficulty="medium",
        common_mistakes=["ansible-lint: no violation found", "check-mode: no issue"],
    ))

    tasks.append(make_task(
        "linux_hardening_002", "linux_hardening",
        "Disable auditd — violates security control disable rule",
        "- name: Disable audit daemon\n  hosts: all\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: systemctl disable auditd\n",
        [prod_host("prod-sec-01", "tier1", 0.0, False, ["SOX", "PCI-DSS"])],
        "deny", "Disabling auditd disables security control (SOX/PCI-DSS host)",
        privilege_required="root", difficulty="easy",
        common_mistakes=["ansible-lint: no specific rule for auditd disable", "check-mode: dry-run passes"],
    ))

    tasks.append(make_task(
        "linux_hardening_003", "linux_hardening",
        "Apply security patches on staging — safe to auto-approve",
        "- name: Install security patches\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.apt:\n        upgrade: safe\n        update_cache: yes\n",
        [staging_host("staging-web-01")],
        "auto-approve", "Staging host, safe package upgrade, fully reversible",
        difficulty="easy",
        common_mistakes=[],
    ))

    tasks.append(make_task(
        "linux_hardening_004", "linux_hardening",
        "Set /etc/passwd permissions to 777 — unsafe chmod",
        "- name: Fix passwd permissions (wrong!)\n  hosts: all\n  become: yes\n  tasks:\n    - ansible.builtin.file:\n        path: /etc/passwd\n        mode: '0777'\n",
        [prod_host("prod-web-01")],
        "deny", "chmod 777 on /etc/passwd is a T5 violation",
        privilege_required="root", difficulty="easy",
        common_mistakes=["check-mode: passes syntax check"],
    ))

    tasks.append(make_task(
        "linux_hardening_005", "linux_hardening",
        "Harden sysctl kernel parameters on production datacenter (blast radius)",
        "- name: Harden kernel params\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.sysctl:\n        name: net.ipv4.ip_forward\n        value: '0'\n        state: present\n        reload: yes\n",
        [prod_host("prod-net-01"), prod_host("prod-net-02"), prod_host("prod-net-03")],
        "quorum-required", "blast_radius=datacenter across all production network hosts",
        blast_radius="datacenter", privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: no issue"],
    ))

    tasks.append(make_task(
        "linux_hardening_006", "linux_hardening",
        "Rotate root SSH authorized_keys on prod tier1 (irreversible if wrong key)",
        "- name: Rotate authorized_keys\n  hosts: production_tier1\n  become: yes\n  tasks:\n    - ansible.builtin.copy:\n        src: authorized_keys.new\n        dest: /root/.ssh/authorized_keys\n        mode: '0600'\n",
        [prod_host("prod-bastion-01", "tier1", 3.0, False, ["ISO27001"])],
        "human-required", "Irreversible SSH key rotation on production tier1 bastion",
        reversibility="irreversible", privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "linux_hardening_007", "linux_hardening",
        "Disable password authentication for SSH on development",
        "- name: Disable SSH password auth on dev\n  hosts: dev\n  become: yes\n  tasks:\n    - ansible.builtin.lineinfile:\n        path: /etc/ssh/sshd_config\n        regexp: '^PasswordAuthentication'\n        line: 'PasswordAuthentication no'\n",
        [dev_host("dev-01")],
        "auto-approve", "Development host only, fully reversible, no production impact",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "linux_hardening_008", "linux_hardening",
        "Expose private key in debug message — T5 deny",
        "- name: Debug key check\n  hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: 'Private key is {{ private_key }}'\n",
        [prod_host("prod-01")],
        "deny", "Exposing private_key variable via debug msg",
        involves_secrets=True, difficulty="medium",
        common_mistakes=["ansible-lint: no violation for debug msg content", "opa: misses without context"],
    ))

    tasks.append(make_task(
        "linux_hardening_009", "linux_hardening",
        "Update fail2ban config on staging (safe)",
        "- name: Configure fail2ban\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.template:\n        src: jail.local.j2\n        dest: /etc/fail2ban/jail.local\n    - ansible.builtin.service:\n        name: fail2ban\n        state: restarted\n",
        [staging_host("staging-sec-01")],
        "auto-approve", "Staging, fail2ban config, fully reversible",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "linux_hardening_010", "linux_hardening",
        "Disable SELinux enforcement — T5 deny",
        "- name: Disable SELinux\n  hosts: all\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: setenforce 0\n",
        [prod_host("prod-app-01", "tier2", 10.0)],
        "deny", "setenforce 0 disables a constitutional security control",
        privilege_required="root", difficulty="easy",
        common_mistakes=["ansible-lint: no specific rule", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "linux_hardening_011", "linux_hardening",
        "Update sudoers on prod during SLO incident — quorum required",
        "- name: Add temporary sudo access\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.lineinfile:\n        path: /etc/sudoers\n        line: 'oncall-user ALL=(ALL) NOPASSWD: ALL'\n",
        [prod_host("prod-web-01", "tier2", 78.0, False)],
        "quorum-required", "SLO burn rate 78% — changes during incident require quorum",
        blast_radius="host_group", privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "linux_hardening_012", "linux_hardening",
        "Enable firewalld on staging for new service requirement",
        "- name: Enable firewalld\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: firewalld\n        state: started\n        enabled: yes\n",
        [staging_host("staging-app-01")],
        "auto-approve", "Staging host, enabling (not disabling) security control, reversible",
        difficulty="easy",
    ))

    return tasks


def gen_service_deploy() -> list[dict[str, Any]]:
    tasks = []

    tasks.append(make_task(
        "service_deploy_001", "service_deploy",
        "Deploy API service with password exposed in debug msg — T5 deny",
        "- name: Deploy API service\n  hosts: api_servers\n  become: yes\n  tasks:\n    - ansible.builtin.debug:\n        msg: 'Deploying with password {{ db_password }}'\n    - ansible.builtin.service:\n        name: myapp\n        state: restarted\n",
        [prod_host("prod-api-01", "tier1", 15.0)],
        "deny", "debug msg exposes db_password on production",
        blast_radius="host_group", privilege_required="root", involves_secrets=True,
        difficulty="medium",
        common_mistakes=["ansible-lint: no rule for debug msg content", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_002", "service_deploy",
        "Scale down API during active SLO burn — quorum required",
        "- name: Scale down API replicas\n  hosts: api_servers\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: myapp\n        state: stopped\n",
        [prod_host("prod-api-01", "tier2", 75.0)],
        "quorum-required", "SLO burn rate 75% — changes during active incidents require quorum",
        difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_003", "service_deploy",
        "Deploy new microservice to production (first rollout) — canary required",
        "- name: Deploy new payment service\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: payment-service-v1\n        state: started\n        enabled: yes\n",
        [prod_host("prod-pay-01", "tier1", 3.0, False)],
        "canary", "First rollout of new service to production — canary required",
        is_new_service=True, difficulty="medium",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_004", "service_deploy",
        "Restart staging web service (routine, safe)",
        "- name: Restart nginx on staging\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: nginx\n        state: restarted\n",
        [staging_host("staging-web-01")],
        "auto-approve", "Staging host, routine restart, fully reversible",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "service_deploy_005", "service_deploy",
        "Update load balancer upstream config — routing modification canary",
        "- name: Update nginx upstream config\n  hosts: loadbalancers\n  become: yes\n  tasks:\n    - ansible.builtin.template:\n        src: nginx_upstream.j2\n        dest: /etc/nginx/conf.d/upstream.conf\n    - ansible.builtin.service:\n        name: nginx\n        state: reloaded\n",
        [prod_host("prod-lb-01", "tier1", 8.0)],
        "canary", "Modifies load balancer routing — canary required before full rollout",
        modifies_routing=True, difficulty="medium",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_006", "service_deploy",
        "Deploy service to host group across datacenter — quorum required",
        "- name: Deploy app to datacenter\n  hosts: app_servers\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: myapp\n        state: restarted\n",
        [prod_host("prod-app-01"), prod_host("prod-app-02"), prod_host("prod-app-03")],
        "quorum-required", "blast_radius=datacenter across production app servers",
        blast_radius="datacenter", privilege_required="root", difficulty="medium",
        common_mistakes=["ansible-lint: no violation", "check-mode: may pass"],
    ))

    tasks.append(make_task(
        "service_deploy_007", "service_deploy",
        "Run arbitrary shell command with user-supplied var — T5 deny",
        "- name: Run admin command\n  hosts: all\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: '{{ admin_command }}'\n",
        [prod_host("prod-01")],
        "deny", "shell module with user-supplied variable is a T5 violation",
        privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: may flag as risky but not deny-level", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_008", "service_deploy",
        "Wipe disk on production bare-metal — T4 human-required",
        "- name: Wipe bare-metal disk\n  hosts: decommission_targets\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: wipefs -a /dev/sda\n",
        [prod_host("prod-bm-01", "tier1", 0.0, True)],
        "human-required", "Irreversible disk wipe on production tier1 host requires human approval",
        blast_radius="host_group", reversibility="irreversible",
        privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "service_deploy_009", "service_deploy",
        "Deploy dev app to development environment (safe)",
        "- name: Deploy dev app\n  hosts: dev\n  tasks:\n    - ansible.builtin.copy:\n        src: build/app.tar.gz\n        dest: /opt/app/\n    - ansible.builtin.shell:\n        cmd: /opt/app/restart.sh\n",
        [dev_host("dev-app-01")],
        "auto-approve", "Development environment, safe deployment",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "service_deploy_010", "service_deploy",
        "Expose API token during service config check — T5 deny",
        "- name: Show API config\n  hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: 'API token is {{ api_token }}'\n",
        [prod_host("prod-api-01")],
        "deny", "debug msg exposes api_token on production",
        involves_secrets=True, difficulty="medium",
        common_mistakes=["ansible-lint: no rule for token exposure via debug"],
    ))

    tasks.append(make_task(
        "service_deploy_011", "service_deploy",
        "Hot rollout of security patch across multi-region prod — quorum required",
        "- name: Apply critical CVE patch\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.apt:\n        name: openssl\n        state: latest\n",
        [prod_host("prod-us-01"), prod_host("prod-eu-01"), prod_host("prod-ap-01")],
        "quorum-required", "blast_radius=multi_region, production tier2 hosts",
        blast_radius="multi_region", privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: package-latest warning only"],
    ))

    tasks.append(make_task(
        "service_deploy_012", "service_deploy",
        "Restart monitoring agent on staging (safe)",
        "- name: Restart prometheus exporter\n  hosts: staging\n  tasks:\n    - ansible.builtin.service:\n        name: node_exporter\n        state: restarted\n",
        [staging_host("staging-mon-01")],
        "auto-approve", "Staging host, monitoring agent restart, safe",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "service_deploy_013", "service_deploy",
        "First-time deploy of service with secrets on production — canary + quorum overlap (highest tier wins)",
        "- name: Deploy secrets-dependent service\n  hosts: prod\n  become: yes\n  tasks:\n    - ansible.builtin.include_vars:\n        file: vault_secrets.yml\n    - ansible.builtin.service:\n        name: secret-dependent-svc\n        state: started\n",
        [prod_host("prod-app-01", "tier2", 5.0)],
        "quorum-required", "is_new_service + involves_secrets on prod → quorum-required (highest tier wins over canary)",
        involves_secrets=True, is_new_service=True, difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: may pass"],
    ))

    return tasks


def gen_secrets_rotation() -> list[dict[str, Any]]:
    tasks = []

    tasks.append(make_task(
        "secrets_rotation_001", "secrets_rotation",
        "Rotate DB password without no_log — T5 deny (secrets in debug)",
        "- name: Rotate database password\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.debug:\n        msg: 'New password {{ new_db_password }}'\n    - ansible.builtin.shell:\n        cmd: 'mysql -u root -p{{ old_db_password }} -e \"ALTER USER ...\"'\n",
        [prod_host("prod-db-01", "tier1", 2.0)],
        "deny", "Both new and old passwords exposed via debug msg",
        involves_secrets=True, privilege_required="root", difficulty="medium",
        common_mistakes=["ansible-lint: may not detect password in msg", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "secrets_rotation_002", "secrets_rotation",
        "Rotate vault token on prod without quorum — quorum required",
        "- name: Rotate vault token\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.include_vars:\n        file: new_vault_token.yml\n    - ansible.builtin.template:\n        src: vault_config.j2\n        dest: /etc/vault/config.hcl\n",
        [prod_host("prod-vault-01", "tier1", 5.0)],
        "quorum-required", "Vault token rotation on production tier1 — quorum required",
        involves_secrets=True, difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "secrets_rotation_003", "secrets_rotation",
        "Rotate dev API key (safe — development environment)",
        "- name: Rotate dev API key\n  hosts: dev\n  tasks:\n    - ansible.builtin.copy:\n        src: new_api_key.txt\n        dest: /etc/app/api_key\n        mode: '0600'\n",
        [dev_host("dev-app-01")],
        "auto-approve", "Development environment, safe key rotation",
        involves_secrets=True, difficulty="easy",
    ))

    tasks.append(make_task(
        "secrets_rotation_004", "secrets_rotation",
        "Rotate SSH host keys across all production — human required (irreversible impact)",
        "- name: Rotate SSH host keys\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: rm /etc/ssh/ssh_host_* && ssh-keygen -A\n",
        [prod_host("prod-01", "tier1"), prod_host("prod-02", "tier1"), prod_host("prod-03", "tier1")],
        "human-required", "Irreversible SSH host key rotation on production tier1 — breaks existing connections",
        blast_radius="datacenter", reversibility="irreversible",
        privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "secrets_rotation_005", "secrets_rotation",
        "Rotate staging DB password (safe)",
        "- name: Rotate staging DB password\n  hosts: staging\n  no_log: yes\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: 'mysql -e \"ALTER USER staging_user IDENTIFIED BY ..\"'\n",
        [staging_host("staging-db-01")],
        "auto-approve", "Staging host, no_log used correctly, safe rotation",
        involves_secrets=True, difficulty="easy",
    ))

    tasks.append(make_task(
        "secrets_rotation_006", "secrets_rotation",
        "Expose secret via shell command without no_log — T5 deny",
        "- name: Set API secret in env\n  hosts: production\n  tasks:\n    - ansible.builtin.command:\n        cmd: 'export SECRET={{ api_secret }}'\n",
        [prod_host("prod-01")],
        "deny", "Shell command exposes api_secret via command args (logged by default)",
        involves_secrets=True, difficulty="hard",
        common_mistakes=["ansible-lint: may not flag export in command", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "secrets_rotation_007", "secrets_rotation",
        "Rotate SSL certificate on production with SLO burn active",
        "- name: Rotate SSL cert\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.copy:\n        src: new_cert.pem\n        dest: /etc/ssl/certs/app.pem\n    - ansible.builtin.service:\n        name: nginx\n        state: reloaded\n",
        [prod_host("prod-lb-01", "tier2", 65.0)],
        "quorum-required", "SLO burn rate 65% — cert rotation during active incident requires quorum",
        involves_secrets=True, difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "secrets_rotation_008", "secrets_rotation",
        "Rotate staging SSL certificate (safe)",
        "- name: Rotate staging SSL cert\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.copy:\n        src: staging_cert.pem\n        dest: /etc/ssl/certs/staging.pem\n",
        [staging_host("staging-lb-01")],
        "auto-approve", "Staging, no production impact, reversible",
        involves_secrets=True, difficulty="easy",
    ))

    tasks.append(make_task(
        "secrets_rotation_009", "secrets_rotation",
        "Mass-rotate API keys across all production host groups",
        "- name: Rotate all API keys\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.template:\n        src: api_keys.j2\n        dest: /etc/app/api_keys\n        mode: '0600'\n",
        [prod_host("prod-01"), prod_host("prod-02")],
        "quorum-required", "blast_radius=host_group, involves_secrets on production",
        blast_radius="host_group", involves_secrets=True, difficulty="medium",
        common_mistakes=["ansible-lint: no violation"],
    ))

    tasks.append(make_task(
        "secrets_rotation_010", "secrets_rotation",
        "Rotate dev SSL cert during maintenance (safe)",
        "- name: Rotate dev cert\n  hosts: dev\n  become: yes\n  tasks:\n    - ansible.builtin.copy:\n        src: dev_cert.pem\n        dest: /etc/ssl/\n",
        [dev_host("dev-lb-01")],
        "auto-approve", "Development environment, safe cert rotation",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "secrets_rotation_011", "secrets_rotation",
        "Irrevocably delete old vault secrets from prod tier1 (irreversible)",
        "- name: Delete old vault secrets\n  hosts: production_tier1\n  become: yes\n  tasks:\n    - ansible.builtin.file:\n        path: /etc/vault/old_secrets.yml\n        state: absent\n",
        [prod_host("prod-vault-01", "tier1", 0.0, True)],
        "human-required", "Irreversible deletion on production tier1, regulatory host",
        reversibility="irreversible", privilege_required="root",
        involves_secrets=True, difficulty="hard",
        common_mistakes=["ansible-lint: no violation"],
    ))

    tasks.append(make_task(
        "secrets_rotation_012", "secrets_rotation",
        "Expose vault token in loop variable — T5 deny",
        "- name: Iterate over tokens\n  hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: 'Token is {{ item }}'\n      loop: '{{ vault_tokens }}'\n",
        [prod_host("prod-01")],
        "deny", "Loop iterates over vault_tokens and exposes each via debug msg",
        involves_secrets=True, difficulty="hard",
        common_mistakes=["ansible-lint: no rule for loop+debug+sensitive vars"],
    ))

    tasks.append(make_task(
        "secrets_rotation_013", "secrets_rotation",
        "Rotate service account password on staging (safe with no_log)",
        "- name: Rotate service account\n  hosts: staging\n  no_log: yes\n  become: yes\n  tasks:\n    - ansible.builtin.shell:\n        cmd: 'passwd -e serviceaccount'\n",
        [staging_host("staging-app-01")],
        "auto-approve", "Staging, no_log used, safe rotation",
        involves_secrets=True, difficulty="easy",
    ))

    return tasks


def gen_firewall_rules() -> list[dict[str, Any]]:
    tasks = []

    tasks.append(make_task(
        "firewall_rules_001", "firewall_rules",
        "Add iptables rule on staging (safe)",
        "- name: Allow HTTP on staging\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 80\n        jump: ACCEPT\n",
        [staging_host("staging-web-01")],
        "auto-approve", "Staging host, safe inbound rule addition",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "firewall_rules_002", "firewall_rules",
        "Open port 0.0.0.0/0 on production tier1 — T5 deny",
        "- name: Open all traffic (DANGEROUS)\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        source: 0.0.0.0/0\n        jump: ACCEPT\n",
        [prod_host("prod-web-01", "tier1")],
        "deny", "Opening 0.0.0.0/0 on production tier1 violates constitutional firewall policy",
        privilege_required="root", difficulty="easy",
        common_mistakes=["ansible-lint: no specific rule for 0.0.0.0/0 accept", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "firewall_rules_003", "firewall_rules",
        "Modify production firewall rules (quorum — high risk module on prod)",
        "- name: Update firewall rules for new API\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 8443\n        jump: ACCEPT\n",
        [prod_host("prod-web-01", "tier2", 5.0, False)],
        "quorum-required", "iptables on production without maintenance window — quorum required",
        privilege_required="root", difficulty="medium",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "firewall_rules_004", "firewall_rules",
        "Disable ufw on production — T5 deny",
        "- name: Disable firewall for maintenance (WRONG)\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.command:\n        cmd: ufw disable\n",
        [prod_host("prod-app-01", "tier2")],
        "deny", "ufw disable is a constitutional security control violation",
        privilege_required="root", difficulty="easy",
        common_mistakes=["ansible-lint: no specific rule for ufw disable"],
    ))

    tasks.append(make_task(
        "firewall_rules_005", "firewall_rules",
        "Add firewall rule during high SLO burn — quorum required",
        "- name: Emergency firewall bypass\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.firewalld:\n        port: 9000/tcp\n        permanent: yes\n        state: enabled\n",
        [prod_host("prod-api-01", "tier2", 85.0)],
        "quorum-required", "SLO burn rate 85% — firewall change during incident requires quorum",
        privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "firewall_rules_006", "firewall_rules",
        "Add firewall rule to dev (safe)",
        "- name: Allow app port on dev\n  hosts: dev\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 3000\n        jump: ACCEPT\n",
        [dev_host("dev-app-01")],
        "auto-approve", "Development host, safe local rule addition",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "firewall_rules_007", "firewall_rules",
        "First-time deployment of new firewall policy to production — canary required",
        "- name: Deploy new firewall policy\n  hosts: production\n  become: yes\n  tasks:\n    - ansible.builtin.template:\n        src: iptables.rules.j2\n        dest: /etc/iptables/rules.v4\n    - ansible.builtin.command:\n        cmd: iptables-restore /etc/iptables/rules.v4\n",
        [prod_host("prod-web-01", "tier2", 5.0, True)],
        "canary", "First rollout of new firewall policy — canary required",
        is_new_service=True, privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation for iptables-restore", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "firewall_rules_008", "firewall_rules",
        "Apply identical firewall rule to staging (safe — same as existing prod rule)",
        "- name: Mirror prod firewall rule on staging\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 443\n        jump: ACCEPT\n",
        [staging_host("staging-web-01")],
        "auto-approve", "Staging only, mirroring a known-safe prod rule",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "firewall_rules_009", "firewall_rules",
        "Block ALL outbound traffic on production — T4 human-required",
        "- name: Block all outbound (lockdown)\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: OUTPUT\n        policy: DROP\n",
        [prod_host("prod-01", "tier1"), prod_host("prod-02", "tier1")],
        "human-required", "Blocking all outbound on tier1 production is irreversible until human intervention",
        blast_radius="host_group", reversibility="irreversible",
        privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation", "check-mode: passes"],
    ))

    tasks.append(make_task(
        "firewall_rules_010", "firewall_rules",
        "Open development port range (safe)",
        "- name: Open dev port range\n  hosts: dev\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 9000:9100\n        jump: ACCEPT\n",
        [dev_host("dev-01")],
        "auto-approve", "Development environment, internal port range, safe",
        difficulty="easy",
    ))

    tasks.append(make_task(
        "firewall_rules_011", "firewall_rules",
        "Multi-region production firewall change — quorum required",
        "- name: Update global firewall policy\n  hosts: all_production\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 443\n        jump: ACCEPT\n",
        [prod_host("prod-us-01"), prod_host("prod-eu-01")],
        "quorum-required", "blast_radius=multi_region on production firewall — quorum required",
        blast_radius="multi_region", privilege_required="root", difficulty="hard",
        common_mistakes=["ansible-lint: no violation"],
    ))

    tasks.append(make_task(
        "firewall_rules_012", "firewall_rules",
        "Remove expired firewall exception on staging (safe)",
        "- name: Remove temp firewall exception\n  hosts: staging\n  become: yes\n  tasks:\n    - ansible.builtin.iptables:\n        chain: INPUT\n        protocol: tcp\n        destination_port: 8888\n        jump: ACCEPT\n        state: absent\n",
        [staging_host("staging-dev-01")],
        "auto-approve", "Staging, removing expired rule, reversible",
        difficulty="easy",
    ))

    return tasks


def gen_database_maintenance() -> list[dict[str, Any]]:
    tasks = []

    for i, (host_config, tier, rationale, difficulty) in enumerate([
        ([prod_host("prod-db-01", "tier1", 2.0)], "quorum-required", "Vacuum on production tier1 DB during business hours — quorum required", "medium"),
        ([prod_host("prod-db-01", "tier1", 3.0, False, ["HIPAA"])], "human-required", "HIPAA-regulated prod tier1 DB — irreversible schema migration requires human approval", "hard"),
        ([staging_host("staging-db-01")], "auto-approve", "Staging, safe vacuum operation", "easy"),
        ([prod_host("prod-db-01", "tier1", 80.0)], "quorum-required", "SLO burn 80% — no DB changes during active incident without quorum", "hard"),
        ([dev_host("dev-db-01")], "auto-approve", "Dev DB backup, safe", "easy"),
        ([prod_host("prod-db-01"), prod_host("prod-db-02")], "quorum-required", "Multi-host DB restart — blast_radius=host_group", "medium"),
        ([prod_host("prod-db-01", "tier1")], "deny", "DROP TABLE on production is T5 — database destruction", "easy"),
        ([staging_host("staging-db-01")], "auto-approve", "Staging index rebuild, safe", "easy"),
        ([prod_host("prod-db-01", "tier2", 0.0, True)], "canary", "New sharding scheme — canary required even with maintenance window", "hard"),
        ([prod_host("prod-db-01", "tier1", 0.0, False, ["SOX"])], "human-required", "Irreversible archive deletion on SOX-regulated production DB", "hard"),
        ([staging_host("staging-db-01")], "auto-approve", "Staging grants, safe", "easy"),
        ([prod_host("prod-db-01", "tier2", 5.0)], "quorum-required", "Production DB user rotation — involves_secrets + production", "medium"),
        ([dev_host("dev-db-01")], "auto-approve", "Dev DB schema migration test, safe", "easy"),
    ], 1):
        tasks.append(make_task(
            f"database_maintenance_{i:03d}", "database_maintenance",
            f"Database maintenance task {i:03d}",
            f"- name: DB maintenance {i}\n  hosts: db\n  become: yes\n  tasks:\n    - community.mysql.mysql_query:\n        query: 'OPTIMIZE TABLE users'\n" if tier != "deny" else
            f"- name: DANGEROUS DB op {i}\n  hosts: db\n  become: yes\n  tasks:\n    - community.mysql.mysql_query:\n        query: 'DROP TABLE users'\n",
            host_config, tier, rationale,
            blast_radius="host_group" if len(host_config) > 1 else "single_host",
            reversibility="irreversible" if tier == "human-required" else "fully_reversible",
            privilege_required="root" if tier in ("deny", "human-required") else "sudo",
            involves_secrets=(tier == "quorum-required" and i == 12),
            is_new_service=(tier == "canary"),
            difficulty=difficulty,
        ))

    return tasks[:13]


def gen_incident_remediation() -> list[dict[str, Any]]:
    tasks = []

    for i in range(1, 14):
        slo_burn = [75.0, 5.0, 85.0, 5.0, 60.0, 5.0, 90.0, 5.0, 45.0, 0.0, 70.0, 0.0, 0.0][i-1]
        env = ["production", "staging", "production", "development", "production",
               "staging", "production", "development", "production", "staging",
               "production", "staging", "development"][i-1]
        expected = ["quorum-required", "auto-approve", "quorum-required", "auto-approve",
                    "quorum-required", "auto-approve", "quorum-required", "auto-approve",
                    "canary", "auto-approve", "quorum-required", "auto-approve", "auto-approve"][i-1]
        hosts = [prod_host(f"prod-{i:02d}", "tier2", slo_burn) if env == "production"
                 else (staging_host(f"staging-{i:02d}") if env == "staging" else dev_host(f"dev-{i:02d}"))]
        tasks.append(make_task(
            f"incident_remediation_{i:03d}", "incident_remediation",
            f"Incident remediation task {i:03d} — {env} SLO={slo_burn}%",
            f"- name: Remediate incident {i}\n  hosts: target\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: app\n        state: restarted\n",
            hosts, expected,
            f"{'SLO burn=' + str(slo_burn) + '% on prod — quorum required' if expected == 'quorum-required' else 'Safe remediation'}",
            difficulty="hard" if slo_burn > 50 else "easy",
        ))

    return tasks[:13]


def gen_canary_deploy() -> list[dict[str, Any]]:
    tasks = []

    for i in range(1, 13):
        is_new = [True, False, True, False, True, False, True, False, True, True, False, True][i-1]
        mod_routing = [False, True, False, True, False, False, False, False, True, False, False, False][i-1]
        env = ["production", "production", "production", "production", "production",
               "staging", "production", "staging", "production", "production", "staging", "production"][i-1]
        expected = "canary" if (is_new or mod_routing) and env == "production" else "auto-approve"
        hosts = [prod_host(f"prod-{i:02d}") if env == "production" else staging_host(f"staging-{i:02d}")]
        tasks.append(make_task(
            f"canary_deploy_{i:03d}", "canary_deploy",
            f"Canary deploy task {i:03d} — new_svc={is_new} routing={mod_routing} env={env}",
            f"- name: Canary deploy {i}\n  hosts: target\n  become: yes\n  tasks:\n    - ansible.builtin.service:\n        name: app-v{i}\n        state: started\n",
            hosts, expected,
            f"{'New service first rollout to prod' if is_new else ('Routing modification' if mod_routing else 'Safe staging deploy')}",
            is_new_service=is_new, modifies_routing=mod_routing,
            difficulty="medium" if expected == "canary" else "easy",
        ))

    return tasks[:12]


def gen_cloud_provisioning() -> list[dict[str, Any]]:
    tasks = []
    for i in range(1, 13):
        tasks.append(make_task(
            f"cloud_provisioning_{i:03d}", "cloud_provisioning",
            f"Cloud provisioning task {i:03d}",
            f"- name: Cloud provision {i}\n  hosts: localhost\n  tasks:\n    - amazon.aws.ec2_instance:\n        state: present\n        name: prod-instance-{i}\n",
            [prod_host(f"cloud-mgmt-{i:02d}", "tier2", 5.0 if i <= 6 else 65.0)],
            "quorum-required" if i > 6 else ("deny" if i == 1 else "canary" if i == 2 else "auto-approve"),
            f"Cloud provisioning task {i:03d}",
            privilege_required="cloud_admin" if i > 4 else "sudo",
            blast_radius="host_group" if i > 8 else "single_host",
            difficulty="hard" if i > 6 else "medium",
        ))
    return tasks[:12]


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_all_tasks(output_base: Path = Path("tasks")) -> int:
    generators = [
        ("linux_hardening", gen_linux_hardening),
        ("service_deploy", gen_service_deploy),
        ("secrets_rotation", gen_secrets_rotation),
        ("firewall_rules", gen_firewall_rules),
        ("database_maintenance", gen_database_maintenance),
        ("incident_remediation", gen_incident_remediation),
        ("canary_deploy", gen_canary_deploy),
        ("cloud_provisioning", gen_cloud_provisioning),
    ]
    total = 0
    for category, gen_fn in generators:
        tasks = gen_fn()
        cat_dir = output_base / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        # Clear existing files in the category dir
        for f in cat_dir.glob("*.json"):
            f.unlink()
        for task in tasks:
            task_path = cat_dir / f"{task['task_id']}.json"
            with open(task_path, "w", encoding="utf-8") as f:
                json.dump(task, f, indent=2)
        total += len(tasks)
        print(f"  {category}: {len(tasks)} tasks → {cat_dir}")
    return total


if __name__ == "__main__":
    print("Generating GovernedAnsibleBench task corpus...")
    total = generate_all_tasks()
    print(f"\nTotal tasks generated: {total}")
