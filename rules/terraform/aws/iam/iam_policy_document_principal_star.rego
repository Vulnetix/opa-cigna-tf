# Intent: aws_iam_policy_document must not grant wildcard principals without conditions.
# Reference: Cigna/confectionery IAM policy document principal star rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_iam_04

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-IAM-04",
	"name": "aws_iam_policy_document must not grant wildcard principals",
	"description": "Allow statements whose principals include \"*\" without a condition block are rejected.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

findings contains finding if {
	some ds in helpers.data_sources("aws_iam_policy_document")
	helpers.has_wildcard_principal_without_condition(ds.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_policy_document %q grants wildcard Principal without Condition.", [ds.name]),
		"artifact_uri": ds.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(ds.content, ds.offset),
		"snippet": sprintf("%s.%s", [ds.type, ds.name]),
	}
}
