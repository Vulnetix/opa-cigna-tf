# Intent: S3 bucket ACLs must not be public or authenticated-read.
# Reference: Cigna/confectionery S3 public ACL rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_s3_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-S3-02",
	"name": "S3 bucket ACLs must not be public or authenticated-read",
	"description": "aws_s3_bucket acl must not start with public- or authenticated-.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
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
	some r in helpers.resources("aws_s3_bucket")
	_is_public_acl(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket %q has a public ACL.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_public_acl(block) if {
	acl := helpers.string_attr(block, "acl")
	startswith(acl, "public")
}

_is_public_acl(block) if {
	acl := helpers.string_attr(block, "acl")
	startswith(acl, "authenticated")
}
