# Intent: RDS instances must not be publicly accessible.
# Reference: Cigna/confectionery RDS public access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rds_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RDS-04",
	"name": "RDS instances must not be publicly accessible",
	"description": "aws_db_instance / aws_rds_cluster_instance must not set publicly_accessible = true.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds"],
}

_rds_types := {"aws_db_instance", "aws_rds_cluster_instance"}

findings contains finding if {
	some t in _rds_types
	some r in helpers.resources(t)
	helpers.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS %q is publicly accessible.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
