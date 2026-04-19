# Intent: Redshift clusters must enable audit logging.
# Reference: Cigna/confectionery Redshift logging rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rs_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RS-02",
	"name": "Redshift clusters must enable audit logging",
	"description": "aws_redshift_cluster must include a logging block.",
	"help_uri": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "logging"],
}

findings contains finding if {
	some r in helpers.resources("aws_redshift_cluster")
	not helpers.has_sub_block(r.block, "logging")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q does not enable logging.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
