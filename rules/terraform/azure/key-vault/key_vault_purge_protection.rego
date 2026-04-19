# Intent: Key Vaults must enable purge protection.
# Reference: Cigna/confectionery Key Vault purge protection rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_kv_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-KV-01",
	"name": "Key Vaults must enable purge protection",
	"description": "azurerm_key_vault must set purge_protection_enabled = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [320],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_key_vault")
	helpers.is_not_true(r.block, "purge_protection_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not set purge_protection_enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
