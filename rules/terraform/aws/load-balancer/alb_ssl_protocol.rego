# Intent: ALB listeners must use HTTPS with a recommended SSL policy.
# Reference: Cigna/confectionery ALB SSL protocol rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_elb_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ELB-02",
	"name": "ALB listeners must use HTTPS with a recommended SSL policy",
	"description": "aws_lb_listener must set protocol = HTTPS, provide a certificate_arn, and use an approved ssl_policy.",
	"help_uri": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
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

_approved := {
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-FS-1-2-Res",
	"ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
}

findings contains finding if {
	some r in helpers.resources("aws_lb_listener")
	not _properly_configured(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ALB listener %q does not use HTTPS with an approved SSL policy.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_properly_configured(block) if {
	helpers.string_attr(block, "protocol") == "HTTPS"
	helpers.has_key(block, "certificate_arn")
	some p in _approved
	helpers.string_attr(block, "ssl_policy") == p
}
