# Intent: DynamoDB tables must encrypt data at rest.
# Reference: Cigna/confectionery DynamoDB encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ddb_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-DDB-01",
	"name": "DynamoDB tables must enable server-side encryption",
	"description": "aws_dynamodb_table must declare a server_side_encryption block with enabled = true.",
	"help_uri": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "dynamodb", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_dynamodb_table")
	not _sse_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DynamoDB table %q does not enable server_side_encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_sse_enabled(block) if {
	some sb in helpers.sub_blocks(block, "server_side_encryption")
	helpers.bool_attr(sb, "enabled") == true
}
