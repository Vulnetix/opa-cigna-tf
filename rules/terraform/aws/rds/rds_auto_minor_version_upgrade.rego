# Intent: RDS instances must enable auto minor version upgrades.
# Reference: Cigna/confectionery RDS auto minor version upgrade rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rds_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RDS-01",
	"name": "RDS DB instances must enable auto minor version upgrades",
	"description": "aws_db_instance must set auto_minor_version_upgrade = true.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds"],
}

findings contains finding if {
	some r in helpers.resources("aws_db_instance")
	helpers.is_not_true(r.block, "auto_minor_version_upgrade")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance %q does not set auto_minor_version_upgrade = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
