# Intent: IAM policies must not grant full administrative permissions.
# Reference: Cigna/confectionery IAM admin policy rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-01",
	"name": "IAM policies must not grant full administrative permissions",
	"description": "Detects IAM policy statements with Effect=Allow, Action=* and Resource=*.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [250],
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
	helpers.has_wildcard_allow_star(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q grants Action=* with Resource=*.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
