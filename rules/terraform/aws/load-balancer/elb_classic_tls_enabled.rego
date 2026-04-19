# Intent: Classic ELBs must have TLS (HTTPS listener + certificate) enabled.
# Reference: Cigna/confectionery Classic ELB TLS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_elb_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ELB-04",
	"name": "Classic ELBs must have TLS (HTTPS listener + certificate) enabled",
	"description": "aws_elb must declare at least one listener with lb_protocol = https and a ssl_certificate_id ARN.",
	"help_uri": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-https-load-balancers.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "load-balancer", "tls"],
}

findings contains finding if {
	some r in helpers.resources("aws_elb")
	not _tls_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Classic ELB %q does not have an HTTPS listener with a certificate.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_tls_enabled(block) if {
	some sb in helpers.sub_blocks(block, "listener")
	helpers.string_attr(sb, "lb_protocol") == "https"
	helpers.has_key(sb, "ssl_certificate_id")
}
