# Intent: S3 bucket policies must not grant wildcard principals without conditions.
# Reference: Cigna/confectionery S3 public policy rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_s3_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-S3-03",
	"name": "S3 bucket policies must not grant wildcard principals without conditions",
	"description": "aws_s3_bucket_policy must not have Effect=Allow with Principal=\"*\" unless a Condition limits access.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3"],
}

findings contains finding if {
	some r in helpers.resources("aws_s3_bucket_policy")
	helpers.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket policy %q grants wildcard Principal without Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
