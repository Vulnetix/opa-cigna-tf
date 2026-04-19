# Intent: ElastiCache replication groups must encrypt at rest and in transit.
# Reference: Cigna/confectionery ElastiCache encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ec_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EC-01",
	"name": "ElastiCache replication groups must enable encryption at rest and in transit",
	"description": "aws_elasticache_replication_group must set at_rest_encryption_enabled and transit_encryption_enabled to true.",
	"help_uri": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/InTransitEncryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elasticache", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_elasticache_replication_group")
	not _fully_encrypted(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ElastiCache replication group %q is missing at-rest or in-transit encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_fully_encrypted(block) if {
	helpers.bool_attr(block, "at_rest_encryption_enabled") == true
	helpers.bool_attr(block, "transit_encryption_enabled") == true
}
