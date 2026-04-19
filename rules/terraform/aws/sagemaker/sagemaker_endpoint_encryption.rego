# Intent: SageMaker endpoints must be encrypted with a KMS key.
# Reference: Cigna/confectionery SageMaker endpoint encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sm_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SM-01",
	"name": "SageMaker endpoints must be encrypted with a KMS key",
	"description": "aws_sagemaker_endpoint_configuration must set kms_key_arn.",
	"help_uri": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sagemaker", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_sagemaker_endpoint_configuration")
	not helpers.has_key(r.block, "kms_key_arn")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SageMaker endpoint configuration %q does not set kms_key_arn.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
