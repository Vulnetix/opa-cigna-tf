# Intent: IAM users must not be declared in Terraform.
# Reference: Cigna/confectionery IAM user creation rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_07

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-07",
	"name": "IAM users must not be declared in Terraform",
	"description": "Workloads should use roles and identity federation. aws_iam_user resources are rejected.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [250],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

findings contains finding if {
	some r in helpers.resources("aws_iam_user")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM user %q should not be declared; use roles and identity federation.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
