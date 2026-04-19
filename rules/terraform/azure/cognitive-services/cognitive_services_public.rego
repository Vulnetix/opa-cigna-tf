# Intent: Cognitive Services must disable public network access.
# Reference: Cigna/confectionery Cognitive Services public access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_cog_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-COG-03",
	"name": "Cognitive Services must disable public network access",
	"description": "azurerm_cognitive_account must set public_network_access_enabled = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/cognitive-services/cognitive-services-virtual-networks",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_cognitive_account")
	helpers.is_not_true(r.block, "public_network_access_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q does not disable public network access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
