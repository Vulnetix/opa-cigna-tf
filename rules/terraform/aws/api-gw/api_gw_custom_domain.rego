# Intent: API Gateway REST APIs should be attached to a custom domain via base-path mapping.
# Reference: Cigna/confectionery API Gateway custom domain rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_apigw_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-APIGW-01",
	"name": "API Gateway REST APIs must have a base-path mapping",
	"description": "Each aws_api_gateway_rest_api should be attached to an aws_api_gateway_base_path_mapping so a custom domain is configured.",
	"help_uri": "https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "apigw"],
}

findings contains finding if {
	some r in helpers.resources("aws_api_gateway_rest_api")
	not _has_mapping(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("API Gateway REST API %q has no aws_api_gateway_base_path_mapping.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_mapping(name) if {
	some m in helpers.resources("aws_api_gateway_base_path_mapping")
	api_id := helpers.string_attr(m.block, "api_id")
	contains(api_id, name)
}
