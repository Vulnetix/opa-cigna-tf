# Intent: S3 buckets must configure server-side encryption with AES256 or aws:kms.
# Reference: Cigna/confectionery S3 encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_s3_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-S3-01",
	"name": "S3 buckets must configure server-side encryption with AES256 or aws:kms",
	"description": "aws_s3_bucket must declare server_side_encryption_configuration with sse_algorithm of AES256 or aws:kms.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_s3_bucket")
	not _has_valid_sse(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket %q is missing server_side_encryption_configuration with AES256 or aws:kms.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_valid_sse(block) if {
	some outer in helpers.sub_blocks(block, "server_side_encryption_configuration")
	regex.match(`sse_algorithm\s*=\s*"(AES256|aws:kms)"`, outer)
}
