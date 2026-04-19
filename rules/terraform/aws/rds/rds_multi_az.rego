# Intent: RDS DB instances must enable Multi-AZ.
# Reference: Cigna/confectionery RDS Multi-AZ rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rds_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RDS-03",
	"name": "RDS DB instances must enable Multi-AZ",
	"description": "aws_db_instance must set multi_az = true unless the engine is Aurora, SQL Server, or DocumentDB.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
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
	not helpers.bool_attr(r.block, "multi_az")
	not _is_exempt(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance %q does not enable Multi-AZ.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_exempt(block) if {
	engine := helpers.string_attr(block, "engine")
	startswith(engine, "aurora")
}

_is_exempt(block) if {
	engine := helpers.string_attr(block, "engine")
	startswith(engine, "sqlserver")
}

_is_exempt(block) if {
	engine := helpers.string_attr(block, "engine")
	startswith(engine, "docdb")
}
