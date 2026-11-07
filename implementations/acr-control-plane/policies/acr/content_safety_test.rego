# OPA tests for the content-level default guardrails (content_safety.rego).
# Run with: opa test policies/ -v
# (CI runs the same command with openpolicyagent/opa:0.70.0.)
#
# The tests pin the documented scope of the defaults:
#   - each deterministic evaluation probe is DENIED;
#   - the rules apply to ANY tool name, not only shell tools;
#   - nested parameters (objects and arrays) are inspected;
#   - legitimate calls are still ALLOWED, including the deliberate
#     conservative boundaries (rm -rf on a relative target, "cd ..",
#     dd to a regular file, redirection to /dev/null, benign base64).
package acr

import future.keywords

# A complete input with the given tool and parameters. Every tool used in
# these tests is allowlisted, so a deny can only come from a content rule
# (or another default rule), never from the allowlist.
base_input(tool, params) := obj if {
	obj := {
		"action": {"tool_name": tool, "parameters": params},
		"agent": {
			"allowed_tools": ["shell_exec", "run_command", "read_file", "issue_refund", "send_email"],
			"forbidden_tools": ["delete_customer"],
			"boundaries": {"max_actions_per_minute": 30, "max_cost_per_hour_usd": 5.0},
		},
		"context": {"actions_this_minute": 0, "hourly_spend_usd": 0.0},
	}
}

# ── Evaluation probes: DENIED ─────────────────────────────────────────────────

test_deny_rm_rf_root if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "rm -rf /"})
	not allow with input as base_input("shell_exec", {"command": "rm -rf /"})
}

# Same payload, different tool name: the rules do not depend on tool_name.
test_deny_rm_rf_root_any_tool if {
	count(deny) > 0 with input as base_input("run_command", {"command": "rm -rf /"})
}

test_deny_rm_rf_root_glob if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "rm -rf /*"})
}

test_deny_rm_no_preserve_root if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "rm --no-preserve-root -rf /"})
}

test_deny_rm_rf_home_tilde if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "rm -rf ~"})
}

test_deny_rm_rf_home_var if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "rm -rf $HOME"})
}

test_deny_path_traversal if {
	count(deny) > 0 with input as base_input("read_file", {"path": "../../etc/passwd"})
	not allow with input as base_input("read_file", {"path": "../../etc/passwd"})
}

# Same payload, different tool name: the rules do not depend on tool_name.
test_deny_path_traversal_any_tool if {
	count(deny) > 0 with input as base_input("run_command", {"path": "../../etc/passwd"})
}

# "cm0gLXJmIC8=" is base64 for "rm -rf /".
test_deny_base64_rm_rf if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "cm0gLXJmIC8="})
	not allow with input as base_input("shell_exec", {"command": "cm0gLXJmIC8="})
}

# Same payload, different tool name: the rules do not depend on tool_name.
test_deny_base64_rm_rf_any_tool if {
	count(deny) > 0 with input as base_input("run_command", {"command": "cm0gLXJmIC8="})
}

# ── Other destructive patterns: DENIED ────────────────────────────────────────

test_deny_mkfs if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "mkfs.ext4 /dev/sda1"})
}

test_deny_dd_to_device if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "dd if=/dev/zero of=/dev/sda bs=1M"})
}

test_deny_fork_bomb if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": ":(){ :|:& };:"})
}

test_deny_chmod_777_root if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "chmod -R 777 /"})
}

test_deny_redirect_to_device if {
	count(deny) > 0 with input as base_input("shell_exec", {"command": "cat log.txt > /dev/sda"})
}

# ── Nested parameters: DENIED ─────────────────────────────────────────────────

test_deny_nested_object_parameter if {
	count(deny) > 0 with input as base_input("shell_exec", {"outer": {"inner": "rm -rf /"}})
}

test_deny_nested_array_parameter if {
	count(deny) > 0 with input as base_input("shell_exec", {"commands": ["echo hi", "rm -rf /"]})
}

# ── Legitimate calls: ALLOWED ─────────────────────────────────────────────────

test_allow_normal_refund if {
	allow with input as base_input("issue_refund", {"amount": 25, "customer_id": "cus_123"})
	count(deny) == 0 with input as base_input("issue_refund", {"amount": 25, "customer_id": "cus_123"})
}

test_allow_normal_email_body if {
	allow with input as base_input("send_email", {"body": "Hello, your order #12345 has shipped. Thank you!"})
	count(deny) == 0 with input as base_input("send_email", {"body": "Hello, your order #12345 has shipped. Thank you!"})
}

test_allow_plain_file_path if {
	allow with input as base_input("read_file", {"path": "/var/data/report.txt"})
	count(deny) == 0 with input as base_input("read_file", {"path": "/var/data/report.txt"})
}

# Deliberate conservative boundary: rm -rf on a relative target is ordinary
# cleanup, not host destruction, and is not blocked by the defaults.
test_allow_rm_rf_relative_target if {
	allow with input as base_input("shell_exec", {"command": "rm -rf ./build"})
	count(deny) == 0 with input as base_input("shell_exec", {"command": "rm -rf ./build"})
}

# Deliberate conservative boundary: ".." without a path-segment boundary
# (here, the argument of cd) is not traversal.
test_allow_cd_dotdot if {
	allow with input as base_input("shell_exec", {"command": "cd .."})
	count(deny) == 0 with input as base_input("shell_exec", {"command": "cd .."})
}

# "aGVsbG8gd29ybGQ=" is base64 for "hello world": decodes to benign text.
test_allow_benign_base64 if {
	allow with input as base_input("send_email", {"body": "aGVsbG8gd29ybGQ="})
	count(deny) == 0 with input as base_input("send_email", {"body": "aGVsbG8gd29ybGQ="})
}

# dd to a regular file is not writing to a device.
test_allow_dd_to_regular_file if {
	allow with input as base_input("shell_exec", {"command": "dd if=/dev/zero of=/tmp/test.img bs=1M count=10"})
	count(deny) == 0 with input as base_input("shell_exec", {"command": "dd if=/dev/zero of=/tmp/test.img bs=1M count=10"})
}

# Redirection to /dev/null is discarding output, not destroying a device.
test_allow_redirect_to_dev_null if {
	allow with input as base_input("shell_exec", {"command": "cat log.txt > /dev/null 2>&1"})
	count(deny) == 0 with input as base_input("shell_exec", {"command": "cat log.txt > /dev/null 2>&1"})
}

# chmod 777 on a named file is not chmod 777 on the filesystem root.
test_allow_chmod_named_file if {
	allow with input as base_input("shell_exec", {"command": "chmod 777 myfile.txt"})
	count(deny) == 0 with input as base_input("shell_exec", {"command": "chmod 777 myfile.txt"})
}
