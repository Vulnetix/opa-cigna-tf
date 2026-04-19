# Intent: ACM certificates should use DNS validation, not EMAIL.
# Reference: Cigna/confectionery ACM rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_aws_acm_01

import rego.v1

import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AWS-ACM-01",
	"name": "ACM certificates must use DNS validation",
	"description": "aws_acm_certificate resources must not set validation_method to EMAIL.",
	"help_uri": "https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-295"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "acm"],
}

findings contains finding if {
	some r in helpers.resources("aws_acm_certificate")
	helpers.string_attr(r.block, "validation_method") == "EMAIL"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ACM certificate %q uses EMAIL validation; use DNS instead.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
