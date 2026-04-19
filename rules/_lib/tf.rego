# Helper package — not a rule (no metadata/findings).
# Shared by the opa-cigna-tf Terraform security rules.
#
# Provides regex-based HCL extraction so rules can scan raw .tf text
# provided via input.file_contents without needing a parsed HCL AST.

package vulnetix.cigna_tf.helpers

import rego.v1

# ── File-type guard ──

is_tf(path) if endswith(lower(path), ".tf")

# ── Line-number from byte offset ──

line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# ── Resource block extraction ──

resource_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}

resources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some block in resource_blocks(content, type)
		name := _block_name(block)
		offset := indexof(content, block)
		r := {"path": path, "block": block, "name": name, "type": type, "offset": offset, "content": content}
	]
}

# ── Data source block extraction ──

data_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)data\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}

data_sources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some block in data_blocks(content, type)
		name := _block_name(block)
		offset := indexof(content, block)
		r := {"path": path, "block": block, "name": name, "type": type, "offset": offset, "content": content}
	]
}

# ── Block name ──

_block_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# ── Attribute readers ──

string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

string_attrs(block, key) := vals if {
	pattern := sprintf(`(?m)%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, -1)
	vals := [v |
		some m in matches
		caps := regex.find_n(`"([^"]*)"`, m, 1)
		count(caps) > 0
		v := trim(caps[0], `"`)
	]
}

bool_attr(block, key) := b if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(true|false)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	b := regex.match(`=\s*true\b`, matches[0])
}

number_attr(block, key) := n if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([0-9]+)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	digits := regex.find_n(`[0-9]+`, matches[0], -1)
	count(digits) > 0
	n := to_number(digits[count(digits) - 1])
}

string_list_attr(block, key) := vals if {
	pattern := sprintf(`(?s)%s\s*=\s*\[([^\]]*)\]`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	body := matches[0]
	items := regex.find_n(`"([^"]*)"`, body, -1)
	vals := [v | some i in items; v := trim(i, `"`)]
}

# ── Structural checks ──

has_key(block, key) if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [key])
	regex.match(pattern, block)
}

has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	subs := regex.find_n(pattern, block, -1)
}

# ── Boolean helpers ──

is_not_true(block, key) if not has_key(block, key)
is_not_true(block, key) if bool_attr(block, key) == false
is_not_true(block, key) if string_attr(block, key) == "false"

is_not_false(block, key) if not has_key(block, key)
is_not_false(block, key) if bool_attr(block, key) == true
is_not_false(block, key) if string_attr(block, key) == "true"

# ── Heredoc extraction ──

heredoc_attrs(block, key) := out if {
	pattern := sprintf(`(?s)%s\s*=\s*<<-?([A-Za-z0-9_]+)\s*\n(.*?)\n\s*\1\b`, [key])
	matches := regex.find_all_string_submatch_n(pattern, block, -1)
	out := [m[2] | some m in matches]
}

# ── IAM policy heuristics ──

has_wildcard_allow_star(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Resource"\s*:\s*"\*"[\s\S]*?"Action"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Action\s*=\s*"\*"[\s\S]*?Resource\s*=\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Resource\s*=\s*"\*"[\s\S]*?Action\s*=\s*"\*"`, block)
}

has_service_star_action(block) if {
	regex.match(`"Action"\s*:\s*"[A-Za-z0-9\-]+:\*"`, block)
}

has_service_star_action(block) if {
	regex.match(`Action\s*=\s*"[A-Za-z0-9\-]+:\*"`, block)
}

has_not_action(block) if {
	regex.match(`"NotAction"\s*:`, block)
}

has_not_action(block) if {
	regex.match(`\bNotAction\s*=`, block)
}

has_wildcard_principal_without_condition(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"`, block)
	not regex.match(`"Condition"\s*:`, block)
}

has_wildcard_principal_without_condition(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*"\*"`, block)
	not regex.match(`"Condition"\s*:`, block)
}
