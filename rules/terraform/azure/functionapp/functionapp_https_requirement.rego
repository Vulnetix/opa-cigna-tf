# Intent: Function Apps must require HTTPS.
# Reference: Cigna/confectionery Function App HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_fa_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-FA-01",
	"name": "Function Apps must require HTTPS",
	"description": "azurerm_function_app must set https_only = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "functionapp"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_function_app")
	helpers.is_not_true(r.block, "https_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App %q does not require HTTPS.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
