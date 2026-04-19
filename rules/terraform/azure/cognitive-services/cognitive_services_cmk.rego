# Intent: Cognitive Services must be encrypted with a customer-managed key.
# Reference: Cigna/confectionery Cognitive Services CMK rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_cog_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-COG-01",
	"name": "Cognitive Services must be encrypted with a customer-managed key",
	"description": "Each azurerm_cognitive_account must have a matching azurerm_cognitive_account_customer_managed_key.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/cognitive-services/encryption/cognitive-services-encryption-keys-portal",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_cognitive_account")
	not _has_cmk(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q has no customer-managed key resource.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_cmk(name) if {
	some cmk in helpers.resources("azurerm_cognitive_account_customer_managed_key")
	cmk_name := helpers.string_attr(cmk.block, "cognitive_account_name")
	contains(cmk_name, name)
}
