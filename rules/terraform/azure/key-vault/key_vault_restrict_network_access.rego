# Intent: Key Vaults must restrict network access.
# Reference: Cigna/confectionery Key Vault network rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_kv_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-KV-03",
	"name": "Key Vaults must restrict network access",
	"description": "azurerm_key_vault network_acls block must set default_action = \"Deny\".",
	"help_uri": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_key_vault")
	not _network_deny(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not set network_acls default_action = Deny.", [r.name]),
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
