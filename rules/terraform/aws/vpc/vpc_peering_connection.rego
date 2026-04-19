# Intent: VPC Peering Connections must not be created.
# Reference: Cigna/confectionery VPC peering rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_vpc_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-VPC-03",
	"name": "VPC Peering Connections must not be created",
	"description": "aws_vpc_peering_connection is disallowed by policy.",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html",
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
	some r in helpers.resources("aws_vpc_peering_connection")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC peering connection %q is disallowed by policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
