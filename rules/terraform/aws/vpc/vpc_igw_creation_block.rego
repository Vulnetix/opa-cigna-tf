# Intent: Internet Gateways must not be created.
# Reference: Cigna/confectionery VPC IGW rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_vpc_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-VPC-02",
	"name": "Internet Gateways must not be created",
	"description": "aws_internet_gateway is disallowed by policy (internet egress must be controlled).",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "vpc"],
}

findings contains finding if {
	some r in helpers.resources("aws_internet_gateway")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Internet Gateway %q is disallowed by policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
