# Intent: SageMaker notebook instances must disable direct internet access.
# Reference: Cigna/confectionery SageMaker internet access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sm_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SM-03",
	"name": "SageMaker notebook instances must disable direct internet access",
	"description": "aws_sagemaker_notebook_instance must not set direct_internet_access = Enabled.",
	"help_uri": "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-additional-configuration.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sagemaker", "network"],
}

findings contains finding if {
	some r in helpers.resources("aws_sagemaker_notebook_instance")
	helpers.string_attr(r.block, "direct_internet_access") == "Enabled"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SageMaker notebook %q allows direct internet access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
