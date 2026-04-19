# Intent: SQS queues must enable server-side encryption.
# Reference: Cigna/confectionery SQS encryption rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sqs_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SQS-02",
	"name": "SQS queues must enable server-side encryption",
	"description": "aws_sqs_queue must set kms_master_key_id.",
	"help_uri": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs", "encryption"],
}

findings contains finding if {
	some r in helpers.resources("aws_sqs_queue")
	not helpers.has_key(r.block, "kms_master_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue %q does not set kms_master_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
