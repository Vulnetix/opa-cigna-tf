# Intent: Logic Apps must require HTTPS.
# Reference: Cigna/confectionery Logic App HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_logic_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-LOGIC-01",
	"name": "Logic Apps must require HTTPS",
	"description": "azurerm_logic_app_standard must set https_only = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/logic-apps/securing-logic-apps-overview",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "logic-app"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_logic_app_standard")
	helpers.is_not_true(r.block, "https_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Logic App %q does not require HTTPS.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
