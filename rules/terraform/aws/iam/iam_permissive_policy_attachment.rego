# Intent: IAM policy attachments must not use overly permissive AWS managed policies.
# Reference: Cigna/confectionery IAM permissive policy attachment rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_03

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-03",
	"name": "IAM policy attachments must not use overly permissive AWS managed policies",
	"description": "Detects attachments of AdministratorAccess, IAMFullAccess, PowerUserAccess and similar managed policies.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
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

_attachment_types := {"aws_iam_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"}

_permissive := {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess", "AmazonS3FullAccess", "AmazonDynamoDBFullAccess"}

findings contains finding if {
	some t in _attachment_types
	some r in helpers.resources(t)
	some p in _permissive
	_arn_contains(r.block, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy attachment %q uses permissive managed policy containing %q.", [r.name, p]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_arn_contains(block, fragment) if {
	arn := helpers.string_attr(block, "policy_arn")
	contains(arn, fragment)
}

_arn_contains(block, fragment) if {
	some arn in helpers.string_list_attr(block, "policy_arns")
	contains(arn, fragment)
}
