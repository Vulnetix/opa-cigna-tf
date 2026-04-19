# Intent: Classic ELB policies must not enable deprecated SSL/TLS protocols.
# Reference: Cigna/confectionery Classic ELB SSL rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_elb_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ELB-03",
	"name": "Classic ELB policies must not enable deprecated SSL/TLS protocols",
	"description": "aws_load_balancer_policy policy_attributes must not enable Protocol-TLSv1, Protocol-SSLv3/SSLv2/SSLv1.",
	"help_uri": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [326],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "load-balancer", "tls"],
}

_deprecated := {"Protocol-TLSv1", "Protocol-SSLv3", "Protocol-SSLv2", "Protocol-SSLv1"}

findings contains finding if {
	some r in helpers.resources("aws_load_balancer_policy")
	some sb in helpers.sub_blocks(r.block, "policy_attribute")
	some d in _deprecated
	helpers.string_attr(sb, "name") == d
	helpers.string_attr(sb, "value") == "true"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Classic ELB policy %q enables deprecated protocol %q.", [r.name, d]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
