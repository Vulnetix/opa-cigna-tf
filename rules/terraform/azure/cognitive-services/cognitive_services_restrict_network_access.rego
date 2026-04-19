# Intent: Cognitive Services must set network_acls default_action = Deny.
# Reference: Cigna/confectionery Cognitive Services network rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_cog_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-COG-04",
	"name": "Cognitive Services must set network_acls default_action = Deny",
	"description": "azurerm_cognitive_account must have a network_acls block with default_action = \"Deny\".",
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
	not _network_deny(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q does not set network_acls default_action = Deny.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_network_deny(block) if {
	some sb in helpers.sub_blocks(block, "network_acls")
	helpers.string_attr(sb, "default_action") == "Deny"
}
