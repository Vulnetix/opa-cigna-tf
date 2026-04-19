# Intent: Security group ingress from 0.0.0.0/0 must be limited to port 80 or 443.
# Reference: Cigna/confectionery security group ingress rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sg_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SG-01",
	"name": "Security group ingress from 0.0.0.0/0 must be limited to port 80 or 443",
	"description": "aws_security_group ingress blocks opening to 0.0.0.0/0 must use port 80 or 443 only.",
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
	_opens_zero_cidr(sb)
	from_port := helpers.number_attr(sb, "from_port")
	not _allowed_port(from_port)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group %q allows ingress from 0.0.0.0/0 on port %d.", [r.name, from_port]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_opens_zero_cidr(block) if {
	regex.match(`0\.0\.0\.0/0`, block)
}

_allowed_port(p) if p == 80
_allowed_port(p) if p == 443
