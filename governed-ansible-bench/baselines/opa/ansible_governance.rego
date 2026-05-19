
package ansible_governance

import future.keywords.if
import future.keywords.in

# T5: DENY — absolute prohibitions

deny_decision[msg] if {
    task := input.tasks[_]
    task.module == "ansible.builtin.debug"
    contains(task.raw_args, "password")
    contains(task.raw_args, "msg")
    msg := "debug-exposes-secret"
}

deny_decision[msg] if {
    task := input.tasks[_]
    task.module in {"ansible.builtin.shell", "ansible.builtin.command"}
    regex.match("systemctl\\s+(stop|disable)\\s+(auditd|firewalld)", task.raw_args)
    msg := "disables-security-control"
}

deny_decision[msg] if {
    contains(input.playbook_content, "chmod 777")
    msg := "world-writable-permission"
}

# T3: QUORUM_REQUIRED

quorum_required if {
    input.blast_radius in {"host_group", "datacenter", "multi_region", "global"}
}

quorum_required if {
    input.involves_secrets == true
    prod_host := input.hosts[_]
    prod_host.environment == "production"
}

quorum_required if {
    burning_host := input.hosts[_]
    burning_host.slo_burn_rate_1h > 50
}

quorum_required if {
    input.privilege_required in {"root", "cloud_admin"}
    prod_host := input.hosts[_]
    prod_host.environment == "production"
}

# T2: CANARY

canary_required if {
    input.is_new_service == true
}

canary_required if {
    input.modifies_routing == true
}

# Final decision
tier = "deny" if { count(deny_decision) > 0 }
tier = "quorum-required" if { count(deny_decision) == 0; quorum_required }
tier = "canary" if { count(deny_decision) == 0; not quorum_required; canary_required }
tier = "auto-approve" if { count(deny_decision) == 0; not quorum_required; not canary_required }

default tier = "auto-approve"
