# Intent: Kinesis streams must be encrypted with a customer-managed KMS key.
# Reference: Cigna/confectionery Kinesis encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_kin_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-KIN-01",
	"name": "Kinesis streams must be encrypted with a customer-managed KMS key",
	"description": "aws_kinesis_stream must set encryption_type = KMS and kms_key_id must not be empty or alias/aws/kinesis.",
	"help_uri": "https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kinesis", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_kinesis_stream")
	_bad_encryption(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Kinesis stream %q is not encrypted with a customer-managed KMS key.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_bad_encryption(block) if {
	helpers.string_attr(block, "encryption_type") != "KMS"
}

_bad_encryption(block) if {
	not helpers.has_key(block, "kms_key_id")
}

_bad_encryption(block) if {
	helpers.string_attr(block, "kms_key_id") == "alias/aws/kinesis"
}
