# Intent: KMS keys must have rotation enabled.
# Reference: Cigna/confectionery KMS rotation rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_kms_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-KMS-01",
	"name": "KMS keys must have rotation enabled",
	"description": "aws_kms_key must not set enable_key_rotation = false (CIS AWS 2.8).",
	"help_uri": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [320],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kms", "cis"],
}

findings contains finding if {
	some r in helpers.resources("aws_kms_key")
	helpers.is_not_true(r.block, "enable_key_rotation")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key %q does not have key rotation enabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
