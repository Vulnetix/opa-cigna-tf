# Intent: RDS backup retention must be at least 7 days.
# Reference: Cigna/confectionery RDS retention rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rds_05

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RDS-05",
	"name": "RDS backup_retention_period must be at least 7 days",
	"description": "aws_db_instance and aws_rds_cluster must set backup_retention_period >= 7.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
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

_rds_types := {"aws_db_instance", "aws_rds_cluster"}

findings contains finding if {
	some t in _rds_types
	some r in helpers.resources(t)
	_retention_too_low(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS %q has backup retention below 7 days.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_retention_too_low(block) if {
	not helpers.has_key(block, "backup_retention_period")
}

_retention_too_low(block) if {
	helpers.number_attr(block, "backup_retention_period") < 7
}
