# Intent: EC2 instances must have an IAM instance profile for SSM/CloudWatch.
# Reference: Cigna/confectionery EC2 instance role rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_ec2_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-EC2-01",
	"name": "EC2 instances must have an IAM instance profile",
	"description": "aws_instance must set iam_instance_profile so SSM and CloudWatch agents can authenticate.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ec2", "iam"],
}

findings contains finding if {
	some r in helpers.resources("aws_instance")
	not helpers.has_key(r.block, "iam_instance_profile")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance %q has no iam_instance_profile.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
