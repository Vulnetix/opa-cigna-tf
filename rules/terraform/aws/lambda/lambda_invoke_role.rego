# Intent: Lambda functions must not reference a role that grants lambda:InvokeFunction.
# Reference: Cigna/confectionery Lambda invoke role rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_lambda_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-LAMBDA-01",
	"name": "Lambda functions must not reference a role that grants lambda:InvokeFunction",
	"description": "Detects aws_lambda_function referencing an aws_iam_role whose assume_role_policy allows lambda.amazonaws.com to call lambda:InvokeFunction.",
	"help_uri": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [250],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "lambda", "iam"],
}

findings contains finding if {
	some fn in helpers.resources("aws_lambda_function")
	role_ref := helpers.string_attr(fn.block, "role")
	_is_invoke_policy(role_ref)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Lambda function %q references a role that may permit lambda:InvokeFunction.", [fn.name]),
		"artifact_uri": fn.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(fn.content, fn.offset),
		"snippet": sprintf("%s.%s", [fn.type, fn.name]),
	}
}

_is_invoke_policy(role_ref) if {
	some role in helpers.resources("aws_iam_role")
	role_name := helpers.string_attr(role.block, "name")
	contains(role_ref, role_name)
	regex.match(`lambda\.amazonaws\.com`, role.block)
	regex.match(`lambda:InvokeFunction`, role.block)
}
