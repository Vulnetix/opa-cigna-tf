# Intent: RDS instances and clusters must encrypt storage with a KMS CMK.
# Reference: Cigna/confectionery RDS encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_rds_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-RDS-02",
	"name": "RDS instances and clusters must encrypt storage with a KMS CMK",
	"description": "aws_db_instance and aws_rds_cluster must set storage_encrypted = true and reference a kms_key_id.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "encryption"],
}

_rds_types := {"aws_db_instance", "aws_rds_cluster"}

findings contains finding if {
	some t in _rds_types
	some r in helpers.resources(t)
	not _encrypted_with_cmk(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS %q is not encrypted with a KMS CMK.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_encrypted_with_cmk(block) if {
	helpers.bool_attr(block, "storage_encrypted") == true
	helpers.has_key(block, "kms_key_id")
}
