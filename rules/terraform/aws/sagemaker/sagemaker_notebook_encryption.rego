# Intent: SageMaker notebook instances must be encrypted with a KMS key.
# Reference: Cigna/confectionery SageMaker notebook encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sm_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SM-02",
	"name": "SageMaker notebook instances must be encrypted with a KMS key",
	"description": "aws_sagemaker_notebook_instance must set kms_key_id.",
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
	some r in helpers.resources("aws_sagemaker_notebook_instance")
	not helpers.has_key(r.block, "kms_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SageMaker notebook %q does not set kms_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
