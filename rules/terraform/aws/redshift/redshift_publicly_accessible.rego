# Intent: Redshift clusters must not be publicly accessible.
# Reference: Cigna/confectionery Redshift public access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rs_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RS-03",
	"name": "Redshift clusters must not be publicly accessible",
	"description": "aws_redshift_cluster must not set publicly_accessible = true.",
	"help_uri": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift"],
}

findings contains finding if {
	some r in helpers.resources("aws_redshift_cluster")
	helpers.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q is publicly accessible.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
