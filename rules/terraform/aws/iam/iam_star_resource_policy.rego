# Intent: Sensitive IAM actions must be scoped to specific resources.
# Reference: Cigna/confectionery IAM star resource policy rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_06

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-06",
	"name": "Sensitive IAM actions must be scoped to specific resources",
	"description": "Detects high-risk actions (iam:PassRole, sts:AssumeRole, iam:CreateRole, s3 get/put, dynamodb get/query) combined with Resource=*.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

_iam_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

_high_risk_patterns := {
	`"Action"\s*:\s*"\*?"`,
	`iam:PassRole`,
	`sts:AssumeRole`,
	`iam:CreateRole`,
	`s3:Get`,
	`s3:Put`,
	`dynamodb:Get`,
	`dynamodb:Query`,
}

findings contains finding if {
	some t in _iam_types
	some r in helpers.resources(t)
	_has_sensitive_action_with_star_resource(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q uses sensitive actions with Resource=*.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_sensitive_action_with_star_resource(block) if {
	regex.match(`(?s)"Action"\s*:\s*(\[?"(?:iam:PassRole|sts:AssumeRole|iam:CreateRole|s3:Get|s3:Put|dynamodb:Get|dynamodb:Query)"`, block)
	regex.match(`"Resource"\s*:\s*"\*"`, block)
}

_has_sensitive_action_with_star_resource(block) if {
	regex.match(`(?s)Action\s*=\s*"(?:iam:PassRole|sts:AssumeRole|iam:CreateRole|s3:Get|s3:Put|dynamodb:Get|dynamodb:Query)"`, block)
	regex.match(`Resource\s*=\s*"\*"`, block)
}
