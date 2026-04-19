# Intent: Application load balancers must enable access logs.
# Reference: Cigna/confectionery ALB access logs rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_elb_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ELB-01",
	"name": "Application load balancers must enable access logs",
	"description": "aws_lb of load_balancer_type \"application\" must declare an access_logs block.",
	"help_uri": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "load-balancer", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_lb")
	helpers.string_attr(r.block, "load_balancer_type") == "application"
	not helpers.has_sub_block(r.block, "access_logs")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ALB %q does not enable access_logs.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
