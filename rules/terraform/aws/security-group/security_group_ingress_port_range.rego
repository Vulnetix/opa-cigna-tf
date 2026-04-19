# Intent: Security groups must not allow all ports.
# Reference: Cigna/confectionery security group port range rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sg_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SG-02",
	"name": "Security groups must not allow all ports",
	"description": "aws_security_group ingress must not set protocol = \"-1\" with from_port = 0 and to_port = 0.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "security-group"],
}

findings contains finding if {
	some r in helpers.resources("aws_security_group")
	some sb in helpers.sub_blocks(r.block, "ingress")
	_all_ports(sb)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group %q allows all ports on ingress.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_all_ports(block) if {
	helpers.string_attr(block, "protocol") == "-1"
	helpers.number_attr(block, "from_port") == 0
	helpers.number_attr(block, "to_port") == 0
}
