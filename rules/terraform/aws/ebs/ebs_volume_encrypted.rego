# Intent: EBS volumes must be encrypted at rest.
# Reference: Cigna/confectionery EBS encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ebs_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EBS-01",
	"name": "EBS volumes must be encrypted at rest",
	"description": "aws_ebs_volume must not set encrypted = false.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ebs", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_ebs_volume")
	helpers.bool_attr(r.block, "encrypted") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume %q is not encrypted at rest.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
