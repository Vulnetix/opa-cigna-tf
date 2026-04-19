# Intent: CloudTrail trails should not be created in application accounts (managed centrally).
# Reference: Cigna/confectionery CloudTrail creation rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ct_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-CT-01",
	"name": "CloudTrail trails must not be created in application accounts",
	"description": "Upstream policy rejects any aws_cloudtrail declaration (trails are managed centrally).",
	"help_uri": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail"],
}

findings contains finding if {
	some r in helpers.resources("aws_cloudtrail")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_cloudtrail resource %q should not be declared at the application layer.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
