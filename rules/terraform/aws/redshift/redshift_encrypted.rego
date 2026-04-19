# Intent: Redshift clusters must be encrypted at rest.
# Reference: Cigna/confectionery Redshift encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rs_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RS-01",
	"name": "Redshift clusters must be encrypted at rest",
	"description": "aws_redshift_cluster must not set encrypted = false.",
	"help_uri": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_redshift_cluster")
	helpers.is_not_true(r.block, "encrypted")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q is not encrypted.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
