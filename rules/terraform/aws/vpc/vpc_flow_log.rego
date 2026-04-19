# Intent: VPCs must have an associated flow log.
# Reference: Cigna/confectionery VPC flow log rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_vpc_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-VPC-01",
	"name": "VPCs must have an associated flow log",
	"description": "Every aws_vpc should have a matching aws_flow_log referencing its vpc_id for traffic visibility.",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "vpc", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_vpc")
	not _has_flow_log(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC %q has no associated flow log.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_flow_log(vpc_name) if {
	some fl in helpers.resources("aws_flow_log")
	vpc_id := helpers.string_attr(fl.block, "vpc_id")
	contains(vpc_id, vpc_name)
}
