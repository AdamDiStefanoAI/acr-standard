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

import future.keywords.contains
import future.keywords.if
import future.keywords.in

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

# Lex a deliberately small shell subset without executing or expanding it.
# Quoted/escaped separators stay inside a word; only unquoted control
# operators and LF newlines end a command. Descriptor redirections such as
# 2>&1 are not separators. CR is a word character, as in POSIX shells.
# Comments end at the next LF newline.
# This is not a shell parser: substitutions, aliases, scripts and dynamically
# constructed commands still require a tool-specific policy or sandbox.
shell_tokens(value) := regex.find_n(
	`#[^\n]*|(?:[^ \t\n'"\\;|&()<>]|\\[^\n]|"(?:\\[\s\S]|[^"\\])*"|'[^']*')+|[<>]+[&|]?|&>>?|&&|\|\||[;|&()\n]`,
	replace(value, "\\\n", ""),
	-1,
)

shell_separator(token) if {
	regex.match(`^[;|&()\n]+$|^#`, token)
}

# Compute separator offsets once rather than rescanning the token list for
# each command. This keeps long compound inputs from quadratic grouping work.
shell_commands(value) := {command |
	tokens := shell_tokens(value)
	separators := {i | some i, token in tokens; shell_separator(token)}
	boundaries := sort({-1, count(tokens)} | separators)
	some i, start in boundaries
	end := boundaries[i + 1]
	command := array.slice(tokens, start + 1, end)
	count(command) > 0
}

# Remove ordinary quoting and escapes while preserving literal $ and ~.
# Keep literal home spellings escaped so they cannot become active
# expansions: '$HOME', "\$HOME" and "~" name literal relative paths.
shell_literal(value) := replace(replace(value, "$", "\\$"), "~", "\\~")

shell_unquoted_part(part) := shell_literal(substring(part, 1, -1)) if {
	startswith(part, "\\")
} else := part

shell_double_quoted_part(part) := shell_literal(substring(part, 1, -1)) if {
	regex.match(`^\\[$\x60"\\]$`, part)
} else := replace(part, "~", "\\~")

shell_part(part) := shell_literal(substring(part, 1, count(part) - 2)) if {
	startswith(part, "'")
} else := concat("", [shell_double_quoted_part(piece) |
	pieces := regex.find_n(`\\[\s\S]|[^\\]+`, substring(part, 1, count(part) - 2), -1)
	piece := pieces[_]
]) if {
	startswith(part, "\"")
} else := shell_unquoted_part(part)

shell_word(word) := concat("", [shell_part(part) |
	parts := regex.find_n(`'[^']*'|"(?:\\[\s\S]|[^"\\])*"|\\[\s\S]|[^'"\\]+`, word, -1)
	part := parts[_]
])

# Redirection destinations are not command operands. Keep them available to
# the separate block-device redirection rule below.
shell_operand(command, i) if {
	i > 0
	not regex.match(`^([<>]+[&|]?|&>>?)$`, command[i])
	not regex.match(`^([<>]+[&|]?|&>>?)$`, command[i - 1])
}

# Scope every command/target pair to a single invocation, never the whole
# parameter value. Absolute executable paths and prefixes such as sudo work.
shell_arguments(value, executable) := {args |
	command := shell_commands(value)[_]
	some i, word in command
	regex.match(sprintf(`(^|/)%s$`, [executable]), shell_word(word))
	args := [shell_word(command[j]) |
		some j
		command[j]
		j > i
		shell_operand(command, j)
	]
}

shell_option(args, i) if {
	args[i]
	not option_terminated(args, i)
}

option_terminated(args, i) if {
	some j
	args[j] == "--"
	j < i
}

rm_recursive(args) if {
	some i, arg in args
	shell_option(args, i)
	regex.match(`^(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)$`, arg)
}

rm_force(args) if {
	some i, arg in args
	shell_option(args, i)
	regex.match(`^(-[a-zA-Z]*f[a-zA-Z]*|--force)$`, arg)
}

# Home expansion is retained symbolically; never read the evaluator's HOME.
# Relative targets such as ./build and /tmp/myapp remain ordinary cleanup.
dangerous_rm_target(arg) if {
	regex.match(`^(/\*?|~(/[\s\S]*)?|\$(HOME|\{HOME\})(/[\s\S]*)?)$`, arg)
}

destructive_shell(value) if {
	args := shell_arguments(value, "rm")[_]
	rm_recursive(args)
	rm_force(args)
	some arg in args
	dangerous_rm_target(arg)
}

# Preserve the documented safety-override rule, but only for this rm's options.
destructive_shell(value) if {
	args := shell_arguments(value, "rm")[_]
	some i
	args[i] == "--no-preserve-root"
	shell_option(args, i)
}

# mkfs requires a path or flag, not a bare mention of the command.
destructive_shell(value) if {
	args := shell_arguments(value, `mkfs(\.[a-z0-9]+)?`)[_]
	regex.match(`^(/\S+|-[a-zA-Z])`, args[_])
}

block_device(value) if {
	regex.match(`^/dev/(sd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|mmcblk[0-9]+|loop[0-9]+|dm-[0-9]+|md[0-9]+|disk[0-9]+|rdisk[0-9]+)`, value)
}

# dd's output must belong to the same command, not a later echo/printf.
destructive_shell(value) if {
	args := shell_arguments(value, "dd")[_]
	some arg in args
	startswith(arg, "of=")
	block_device(substring(arg, 3, -1))
}

# The fork bomb: :(){ :|:& };: (whitespace-tolerant).
destructive_shell(value) if {
	regex.match(`:\(\)`, value)
	regex.match(`:\s*\|\s*:`, value)
	regex.match(`&\s*\}\s*;`, value)
}

# chmod 777 on the filesystem root, including ordinary quoted operands.
destructive_shell(value) if {
	args := shell_arguments(value, "chmod")[_]
	some i, arg in args
	arg == "777"
	some j
	j > i
	regex.match(`^/\*?$`, args[j])
}

# Shell redirection to a block device, including quoted destinations.
# /dev/null remains outside the device list.
destructive_shell(value) if {
	command := shell_commands(value)[_]
	some i, token in command
	regex.match(`^(>>?|>\||>&|&>>?)$`, token)
	block_device(shell_word(command[i + 1]))
}

# ── Path traversal ────────────────────────────────────────────────────────────
# Standalone paths and path-bearing arguments (including quoted arguments and
# --option=../path) are covered. Bare ".." arguments such as "cd .." remain
# outside this heuristic; dot-containing names and ellipses are not segments.
path_traversal(value) if {
	regex.match(`(^|[/\\])\.\.(/|\\|[\s'";|&)]|$)`, value)
}

path_traversal(value) if {
	regex.match(`(^|[\s'"=;|&(])\.\.[/\\]`, value)
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
