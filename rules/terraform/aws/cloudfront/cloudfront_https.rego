# Intent: CloudFront viewer protocol must enforce HTTPS.
# Reference: Cigna/confectionery CloudFront HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_cf_02

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-CF-02",
	"name": "CloudFront viewer protocol must enforce HTTPS",
	"description": "default_cache_behavior.viewer_protocol_policy must be redirect-to-https or https-only.",
	"help_uri": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewer-protocol.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "https"],
}

findings contains finding if {
	some r in helpers.resources("aws_cloudfront_distribution")
	some sb in helpers.sub_blocks(r.block, "default_cache_behavior")
	v := helpers.string_attr(sb, "viewer_protocol_policy")
	not _is_https(v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q permits HTTP traffic (viewer_protocol_policy=%q).", [r.name, v]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_https(v) if v == "redirect-to-https"
_is_https(v) if v == "https-only"
