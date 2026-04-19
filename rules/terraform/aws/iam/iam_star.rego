# Intent: IAM policies must list service actions, not service:* wildcards.
# Reference: Cigna/confectionery IAM service star rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_05

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-05",
	"name": "IAM policies must list service actions, not service:* wildcards",
	"description": "Detects Action values matching <service>:* in policies that allow on Resource=*.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

_iam_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

findings contains finding if {
	some t in _iam_types
	some r in helpers.resources(t)
	helpers.has_service_star_action(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q uses a <service>:* wildcard action.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
