# Intent: Cognitive Services must disable local authentication.
# Reference: Cigna/confectionery Cognitive Services local auth rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_cog_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-COG-02",
	"name": "Cognitive Services must disable local authentication",
	"description": "azurerm_cognitive_account must set local_auth_enabled = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/cognitive-services/authentication",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [287],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_cognitive_account")
	helpers.is_not_true(r.block, "local_auth_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q does not disable local authentication.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
