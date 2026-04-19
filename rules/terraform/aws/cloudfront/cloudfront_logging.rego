# Intent: CloudFront distributions must configure access logging.
# Reference: Cigna/confectionery CloudFront logging rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_cf_03

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-CF-03",
	"name": "CloudFront distributions must configure access logging",
	"description": "aws_cloudfront_distribution must include a logging_config block.",
	"help_uri": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_cloudfront_distribution")
	not helpers.has_sub_block(r.block, "logging_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q does not enable logging_config.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
