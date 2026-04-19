# Intent: SNS topics must configure server-side encryption.
# Reference: Cigna/confectionery SNS encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sns_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SNS-01",
	"name": "SNS topics must configure server-side encryption",
	"description": "aws_sns_topic must set kms_master_key_id.",
	"help_uri": "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sns", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_sns_topic")
	not helpers.has_key(r.block, "kms_master_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SNS topic %q does not set kms_master_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
