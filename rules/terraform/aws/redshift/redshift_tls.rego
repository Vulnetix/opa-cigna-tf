# Intent: Redshift parameter groups must enforce SSL.
# Reference: Cigna/confectionery Redshift TLS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rs_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RS-04",
	"name": "Redshift parameter groups must enforce SSL",
	"description": "aws_redshift_parameter_group must include a parameter block { name = \"require_ssl\", value = \"true\" }.",
	"help_uri": "https://docs.aws.amazon.com/redshift/latest/mgmt/configuring-ssl-connections.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "tls"],
}

findings contains finding if {
	some r in helpers.resources("aws_redshift_parameter_group")
	not _requires_ssl(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift parameter group %q does not set require_ssl = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_requires_ssl(block) if {
	some sb in helpers.sub_blocks(block, "parameter")
	helpers.string_attr(sb, "name") == "require_ssl"
	helpers.string_attr(sb, "value") == "true"
}
