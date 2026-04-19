# Intent: IAM policies must not use NotAction.
# Reference: Cigna/confectionery IAM NotAction rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_02

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-02",
	"name": "IAM policies must not use NotAction",
	"description": "Detects NotAction elements in IAM policy documents — Action should be used instead.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
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
	helpers.has_not_action(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q uses NotAction; use Action instead.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
