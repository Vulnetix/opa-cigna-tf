# Intent: API Gateway stages must enable access logging.
# Reference: Cigna/confectionery API Gateway logging rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_apigw_02

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-APIGW-02",
	"name": "API Gateway stages must enable access logging",
	"description": "aws_api_gateway_stage must include an access_log_settings block so requests are logged.",
	"help_uri": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "apigw", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_api_gateway_stage")
	not helpers.has_sub_block(r.block, "access_log_settings")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("API Gateway stage %q does not configure access_log_settings.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
