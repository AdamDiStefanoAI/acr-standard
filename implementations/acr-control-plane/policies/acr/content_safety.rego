# ACR Content Safety Policy Rules
# Default content-level guardrails (package acr).
#
# Until this file, the default policies were tool-name-level only: they checked
# input.action.tool_name against allowlists (see common.rego) and never
# inspected what an allowlisted tool was asked to do. An operator who
# allowlisted a shell tool therefore got zero out-of-the-box protection
# against destructive commands, encoded payloads, or path traversal
# (GitHub issue #46; independent evaluation 2026-10-19).
#
# These rules close the deterministic part of that gap. They inspect EVERY
# string value anywhere inside input.action.parameters, at any depth
# (objects, arrays, nested objects), regardless of tool_name. A rule fires
# for any tool, not only for shell tools.
#
# Covered (deterministic patterns only):
#   1. Destructive shell commands (rm -rf on a protected target, mkfs,
#      dd to a block device, the fork bomb, chmod 777 on /, shell
#      redirection to a block device).
#   2. Path traversal (".." as a path segment).
#   3. Base64-encoded destructive payloads (decoded and re-checked against
#      the destructive shell patterns).
#
# NOT covered, by design:
#   - Prompt injection. Detecting injected instructions needs a dedicated
#     detector; these defaults make no claim to detect it. Operators who
#     need prompt-injection protection must add a detector of their own.
#   - Operator-specific rules for their own tools. These defaults protect
#     the common destructive cases; they are not a substitute for
#     per-tool parameter rules.
#
# The patterns are deliberately narrow: each destructive rule requires the
# dangerous command AND its dangerous target, so ordinary prose and
# ordinary commands (for example "rm -rf ./build" or "chmod 777 myfile")
# do not match. Where a pattern or a boundary was ambiguous, the
# conservative option (fewer false positives) was chosen.
package acr

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ── String parameter values ───────────────────────────────────────────────────
# Every string value anywhere inside input.action.parameters, at any depth.
# Non-string values are ignored. If parameters are absent, this set is empty
# and no content rule fires.
all_string_parameter_values contains value if {
	walk(input.action.parameters, [_, value])
	is_string(value)
}

# ── Destructive shell patterns ────────────────────────────────────────────────
# Intent: block commands that would destroy the host filesystem or storage.
# Each rule requires the dangerous command AND its dangerous target.
# Block device names covered: sd*, hd*, nvme*n*, vd*, xvd*, mmcblk*,
# loop*, dm-*, md*, disk* (macOS), rdisk* (macOS raw disk).

# rm with recursive + force flags, combined (-rf, -fr) or split (-r -f, -f -r).
rm_recursive_force(value) if {
	regex.match(`\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b`, value)
}

rm_recursive_force(value) if {
	regex.match(`\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b`, value)
}

rm_recursive_force(value) if {
	regex.match(`\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+-[a-zA-Z]*f[a-zA-Z]*\b`, value)
}

rm_recursive_force(value) if {
	regex.match(`\brm\s+-[a-zA-Z]*f[a-zA-Z]*\s+-[a-zA-Z]*r[a-zA-Z]*\b`, value)
}

# A target that makes recursive force-remove destructive: filesystem root,
# the home directory, or the --no-preserve-root safety override. A relative
# target such as ./build or /tmp/myapp is deliberately NOT covered: removing
# it is an ordinary cleanup, not host destruction.
dangerous_rm_target(value) if {
	regex.match(`--no-preserve-root`, value)
}

dangerous_rm_target(value) if {
	regex.match(`\s/\*?(\s|$|;|\||&)`, value)
}

dangerous_rm_target(value) if {
	regex.match(`\s~(\s|/|$|;|\||&)`, value)
}

dangerous_rm_target(value) if {
	regex.match(`\s\$HOME(\s|/|$|;|\||&)`, value)
}

# True when the value contains a destructive shell command.
destructive_shell(value) if {
	rm_recursive_force(value)
	dangerous_rm_target(value)
}

# rm with the safety override is destructive regardless of flags or target.
destructive_shell(value) if {
	regex.match(`\brm\b`, value)
	regex.match(`--no-preserve-root`, value)
}

# mkfs formats a filesystem; require a target path or flag so bare prose
# mentioning mkfs does not match.
destructive_shell(value) if {
	regex.match(`\bmkfs(\.[a-z0-9]+)?\s+(/\S+|-[a-zA-Z])`, value)
}

# dd writing to a block device (of=/dev/<device>). Writing to /dev/null or
# to a regular file is not covered.
destructive_shell(value) if {
	regex.match(`\bdd\b`, value)
	regex.match(`\bof=/dev/(sd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|mmcblk[0-9]+|loop[0-9]+|dm-[0-9]+|md[0-9]+|disk[0-9]+|rdisk[0-9]+)`, value)
}

# The fork bomb: :(){ :|:& };: (whitespace-tolerant).
destructive_shell(value) if {
	regex.match(`:\(\)`, value)
	regex.match(`:\s*\|\s*:`, value)
	regex.match(`&\s*\}\s*;`, value)
}

# chmod 777 on the filesystem root. A root target is required; chmod 777 on
# a named file or directory is ordinary (if careless) administration.
destructive_shell(value) if {
	regex.match(`\bchmod\s+(?:-[a-zA-Z]*[Rr][a-zA-Z]*\s+)?777\s+/\*?(\s|$|;|\||&)`, value)
}

# Shell redirection to a block device (>, >>, 2>, 2>>). Redirection to
# /dev/null is excluded by the device list and is not covered.
destructive_shell(value) if {
	regex.match(`[0-9]?>>?\s*/dev/(sd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|mmcblk[0-9]+|loop[0-9]+|dm-[0-9]+|md[0-9]+|disk[0-9]+|rdisk[0-9]+)`, value)
}

# ── Path traversal ────────────────────────────────────────────────────────────
# Intent: block ".." used as a path segment (for example ../../etc/passwd).
# A segment boundary is required on both sides, so "file..txt", "...", and
# "cd .." do not match. The terminators cover slash, backslash, command
# separators, and end of string.
path_traversal(value) if {
	regex.match(`(^|[/\\])\.\.(/|\\|;|\||&|$)`, value)
}

# ── Base64-encoded destructive payloads ───────────────────────────────────────
# Intent: catch destructive commands hidden behind base64 encoding
# (for example "cm0gLXJmIC8=" decodes to "rm -rf /").
# Only whole values that look like base64 are decoded: at least 8
# characters, length a multiple of 4, base64 alphabet with optional padding.
# The decoded content must be printable text before it is re-checked, so
# arbitrary binary decodes never match. Decoded content is re-checked
# against the destructive shell patterns only (not path traversal).
decode_base64_text(value) := decoded if {
	count(value) >= 8
	count(value) % 4 == 0
	regex.match(`^[A-Za-z0-9+/]+={0,2}$`, value)
	decoded := base64.decode(value)
	regex.match(`^[\x20-\x7e\r\n\t]*$`, decoded)
}

# ── Deny rules ────────────────────────────────────────────────────────────────
# Intent: a destructive shell command in ANY string parameter of ANY tool
# is denied before execution. Tool-name allowlisting is not a bypass.
deny contains reason if {
	some value in all_string_parameter_values
	destructive_shell(value)
	reason := "Destructive shell command blocked: content-level default policy"
}

# Intent: a path traversal in ANY string parameter of ANY tool is denied
# before execution.
deny contains reason if {
	some value in all_string_parameter_values
	path_traversal(value)
	reason := "Path traversal blocked: '..' used as a path segment"
}

# Intent: a base64-encoded destructive shell command in ANY string parameter
# of ANY tool is denied before execution.
deny contains reason if {
	some value in all_string_parameter_values
	decoded := decode_base64_text(value)
	destructive_shell(decoded)
	reason := "Base64-encoded destructive shell command blocked: content-level default policy"
}
