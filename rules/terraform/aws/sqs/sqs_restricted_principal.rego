# Intent: SQS queue policies must not grant wildcard Principal without Condition.
# Reference: Cigna/confectionery SQS restricted principal rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sqs_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SQS-01",
	"name": "SQS queue policies must not grant wildcard Principal without Condition",
	"description": "aws_sqs_queue_policy with Effect=Allow and Principal=\"*\" must include a Condition.",
	"help_uri": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-iam-policies.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs"],
}

findings contains finding if {
	some r in helpers.resources("aws_sqs_queue_policy")
	helpers.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue policy %q grants wildcard Principal without Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
