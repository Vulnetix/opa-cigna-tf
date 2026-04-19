# Intent: CloudTrail must enable log file validation for tamper detection.
# Reference: Cigna/confectionery CloudTrail log file validation rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ct_02

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-CT-02",
	"name": "CloudTrail must enable log file validation",
	"description": "aws_cloudtrail must set enable_log_file_validation = true (CIS AWS 2.2).",
	"help_uri": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [354],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail", "cis"],
}

findings contains finding if {
	some r in helpers.resources("aws_cloudtrail")
	helpers.bool_attr(r.block, "enable_log_file_validation") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q has enable_log_file_validation disabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
