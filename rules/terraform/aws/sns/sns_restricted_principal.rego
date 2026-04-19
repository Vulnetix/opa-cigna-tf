# Intent: SNS topic policies must not grant wildcard Principal without Condition.
# Reference: Cigna/confectionery SNS restricted principal rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_sns_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-SNS-02",
	"name": "SNS topic policies must not grant wildcard Principal without Condition",
	"description": "aws_sns_topic_policy with Effect=Allow and Principal=\"*\" must include a Condition.",
	"help_uri": "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language.html",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sns"],
}

findings contains finding if {
	some r in helpers.resources("aws_sns_topic_policy")
	helpers.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SNS topic policy %q grants wildcard Principal without Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
