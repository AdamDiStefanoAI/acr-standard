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
# Keep tests out of data.acr: the gateway queries that entire runtime package.
# File-mounted OPA development instances must not evaluate tests per request.
package acr_test

import data.acr.allow
import data.acr.deny

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

# Shell quoting and command-boundary regressions. These strings are only
# policy inputs: no test executes a shell command.

test_deny_quoted_protected_targets if {
	every command in [
		"rm -rf \"$HOME\"",
		"rm -rf \"${HOME}\"",
		"rm -rf \"$HOME/cache\"",
		"rm -rf \"$HOME/cache\nname\"",
		"rm -rf ~/\"cache\nname\"",
		"rm -rf \"/\"",
		"rm -rf '/'",
		"rm -rf \"/*\"",
		"rm -rf '/*'",
		"rm -rf /\"\"",
		"rm -rf \"\"/",
		"rm -rf \\/",
		"rm \"-rf\" \"/\"",
		"/bin/rm -rf \"$HOME\"",
		"sudo rm -rf \"$HOME\"",
		"rm -r -f \"/\"",
		"rm -f -r \"/\"",
		"rm --recursive --force /",
	] {
		count(deny) > 0 with input as base_input("shell_exec", {"command": command})
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_protected_targets_in_compounds if {
	every command in [
		"echo ready && rm -rf \"$HOME\"",
		"ls /; rm -rf \"$HOME\"",
		"rm -rf ./build || rm -rf \"$HOME\"",
		"rm -rf ./build\nrm -rf /",
		"rm -rf ./build & rm -rf /",
		"rm -rf ./build | rm -rf /",
		"(rm -rf /)",
		"rm -rf \"./build;cache\" \"$HOME\"",
		"rm -rf \"./build&&cache\" /",
		"rm -rf ./build\\;cache /",
		"rm -rf \\\n\"$HOME\"",
		"rm -rf ./build # comment\nrm -rf /",
	] {
		count(deny) > 0 with input as base_input("shell_exec", {"command": command})
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

test_allow_separate_safe_commands if {
	every command in [
		"rm -rf ./build && ls /",
		"rm -rf ./build; ls /",
		"rm -rf ./build || ls /",
		"rm -rf ./build | ls /",
		"rm -rf ./build & ls /",
		"rm -rf ./build\nls /",
		"rm -rf ./build\r\nls /",
		"ls / && rm -rf ./build",
		"rm -rf ./build && echo --no-preserve-root",
		"rm ./build; echo --no-preserve-root",
		"dd if=/dev/zero of=./test.img && echo of=/dev/sda",
		"dd if=/dev/zero of=./test.img\necho of=/dev/sda",
		"chmod 777 myfile.txt && ls /",
		"rm -rf ./build # / --no-preserve-root",
		"rm -rf ./build </",
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_allow_literal_and_nonprotected_operands if {
	every command in [
		"rm -rf '$HOME'",
		"rm -rf '${HOME}'",
		"rm -rf \"\\$HOME\"",
		"rm -rf \\$HOME",
		"rm -rf \"~\"",
		"rm -rf '~'",
		"rm -rf \\~",
		"rm -rf \"$HOMELESS\"",
		"rm -rf \"/tmp/myapp\"",
		"rm -rf \"./build /\"",
		"rm -rf \"./build; /\"",
		"rm -rf -- --no-preserve-root",
		"rm -- -rf /",
		"rm -r ./build -f-not-an-option /tmp/myapp",
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_quoted_other_destructive_targets if {
	every command in [
		"mkfs.ext4 \"/dev/sda1\"",
		"mkfs '/dev/sda1'",
		"dd if=/dev/zero of=\"/dev/sda\"",
		"dd if=/dev/zero 'of=/dev/sda'",
		"chmod -R 777 \"/\"",
		"chmod 777 '/'",
		"cat log.txt > \"/dev/sda\"",
		"cat log.txt >> '/dev/sda'",
		"cat log.txt 2> \"/dev/sda\"",
	] {
		count(deny) > 0 with input as base_input("shell_exec", {"command": command})
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

test_allow_quoted_safe_device_targets if {
	every command in [
		"dd if=/dev/zero of=\"/tmp/test.img\"",
		"dd if=/dev/zero of=\"/dev/null\"",
		"cat log.txt > \"/dev/null\"",
		"chmod 777 \"myfile.txt\"",
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_traversal_arguments if {
	every command in [
		"cat ../secret.txt",
		"cat \"../secret.txt\"",
		"cat '../secret.txt'",
		"cat ..\\secret.txt",
		"cat \"..\\secret.txt\"",
		"cat --input=../secret.txt",
		"cat --input=\"../secret.txt\"",
		"cat ./folder/.. ",
		"cat \"./folder/..\"",
		"cat folder/../secret.txt",
		"cat ../secret.txt && echo done",
		"cat;cat ../secret.txt",
		"../secret.txt",
		"..\\secret.txt",
	] {
		count(deny) > 0 with input as base_input("shell_exec", {"command": command})
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

test_allow_traversal_boundary_lookalikes if {
	every command in [
		"cd ..",
		"cd \"..\"",
		"cd '..'",
		"echo ...",
		"cat file..txt",
		"cat .../secret.txt",
		"cat dir..name/secret.txt",
		"cat \"file..txt\"",
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

# Whole-value base64 uses the same quote-aware checks and command boundaries.
test_deny_base64_quoted_home if {
	encoded := base64.encode("rm -rf \"$HOME\"")
	count(deny) > 0 with input as base_input("run_command", {"payload": encoded})
	not allow with input as base_input("run_command", {"payload": encoded})
}

test_allow_base64_separate_safe_commands if {
	encoded := base64.encode("rm -rf ./build && ls /")
	allow with input as base_input("shell_exec", {"payload": encoded})
	count(deny) == 0 with input as base_input("shell_exec", {"payload": encoded})
}

test_deny_nested_quoted_home_any_tool if {
	params := {"outer": [{"command": "rm -rf \"$HOME\""}]}
	count(deny) > 0 with input as base_input("send_email", params)
	not allow with input as base_input("send_email", params)
}

test_deny_nested_traversal_argument_any_tool if {
	params := {"outer": [{"command": "cat ../secret.txt"}]}
	count(deny) > 0 with input as base_input("send_email", params)
	not allow with input as base_input("send_email", params)
}

# Descriptor duplication and literal carriage returns do not terminate a shell
# invocation. Keep flags and targets connected across ordinary redirections.
test_deny_redirections_inside_destructive_command if {
	every command in [
		"rm -rf 2>&1 $HOME",
		"rm -rf 2>&1 \"$HOME\"",
		"rm -rf 0<&3 /",
		"rm -rf &>/tmp/log /",
		"rm -rf &>>/tmp/log /",
		"rm -rf >|/tmp/log /",
		"dd 2>&1 of=/dev/sda",
		"chmod 777 2>&1 /",
		"rm -rf ./build\r $HOME",
		"cat log.txt >&/dev/sda",
		"cat log.txt &>/dev/sda",
		"cat log.txt &>>/dev/sda",
		"cat log.txt >|/dev/sda",
	] {
		count(deny) > 0 with input as base_input("shell_exec", {"command": command})
		not allow with input as base_input("shell_exec", {"command": command})
		encoded := base64.encode(command)
		not allow with input as base_input("shell_exec", {"command": encoded})
	}
}

test_allow_safe_descriptor_redirection if {
	every command in [
		"rm -rf ./build 2>&1 && ls /",
		"rm -rf ./build &>/tmp/log; ls /",
		"rm -rf ./build >|/tmp/log; ls /",
		"dd 2>&1 of=./test.img; echo of=/dev/sda",
		"cat log.txt &>/dev/null",
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

# Quoting cannot assemble a new variable name or activate a literal tilde.
test_allow_mixed_quoted_literal_home if {
	every command in [
		`rm -rf ""~`,
		`rm -rf ~"/"`,
		`rm -rf ~''/`,
		`rm -rf $H""OME`,
		`rm -rf "$H"OME`,
		`rm -rf "$"HOME`,
		`rm -rf $HO'ME'`,
		`rm -rf ${H}OME`,
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_active_home_expansion_with_quoted_suffix if {
	every command in [
		`rm -rf $HOME""`,
		`rm -rf "$HOME"/`,
		`rm -rf ${HOME}''`,
		`rm -rf ~/""`,
	] {
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

# The chmod mode is the first non-option operand, not a later filename.
test_allow_chmod_777_filename if {
	every command in [
		`chmod 755 777 /`,
		`chmod -R 755 777 /`,
		`chmod -- 755 777 /`,
		`chmod --reference=777 /`,
		`chmod --reference 777 /`,
		`chmod -w 777 /`,
		`chmod -R -w 777 /`,
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_chmod_actual_mode_with_options if {
	every command in [
		`chmod -- 777 /`,
		`chmod -R -- 777 /`,
		`chmod 2>&1 777 /`,
		`chmod -R 2>/tmp/log 777 /`,
	] {
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

# Quote removal joins path pieces, but quoted boundaries are not path separators.
test_deny_concatenated_quoted_traversal if {
	every command in [
		`cat '..'/secret.txt`,
		`cat "."'./secret.txt'`,
		`cat --input='..'/secret.txt`,
		`cat 'folder/..'/secret.txt`,
		`cat "folder/.."`,
		`sh -c 'cat ".."/secret.txt'`,
	] {
		not allow with input as base_input("shell_exec", {"command": command})
	}
}

test_allow_quoted_traversal_lookalike_suffix if {
	every command in [
		`cat "./folder/.."suffix`,
		`cat './folder/..'suffix`,
		`cat ".."suffix/secret.txt`,
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}

test_deny_explicit_shell_command_strings if {
	every command in [
		`sh -c 'rm -rf $HOME'`,
		`sh -c 'rm -rf $HOME;'`,
		`bash -c 'rm -rf $HOME '`,
		`sh -c 'rm -rf "$HOME"'`,
		`bash -lc 'rm -rf /'`,
		`sh -o errexit -c 'rm -rf /'`,
		`sudo /bin/sh -c 'dd of=/dev/sda'`,
		`sh -c "chmod 777 /"`,
	] {
		not allow with input as base_input("shell_exec", {"command": command})
		encoded := base64.encode(command)
		not allow with input as base_input("shell_exec", {"command": encoded})
	}
}

test_allow_explicit_safe_shell_command_strings if {
	every command in [
		`sh -c 'rm -rf ./build && ls /'`,
		`sh -c 'rm -rf \$HOME'`,
		`sh -c 'rm -rf "~"'`,
		`sh -c 'chmod 755 777 /'`,
		`sh -c 'printf hello' 'rm -rf /'`,
		`sh -c 'printf hello' -c 'rm -rf /'`,
		`sh -c 'printf hello' sh -c 'rm -rf /'`,
		`sh script.sh -c 'rm -rf /'`,
		`sh -- -c 'rm -rf /'`,
	] {
		allow with input as base_input("shell_exec", {"command": command})
		count(deny) == 0 with input as base_input("shell_exec", {"command": command})
	}
}
