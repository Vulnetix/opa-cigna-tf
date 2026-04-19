# Intent: Key Vaults must enable RBAC authorization.
# Reference: Cigna/confectionery Key Vault RBAC rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_kv_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-KV-02",
	"name": "Key Vaults must enable RBAC authorization",
	"description": "azurerm_key_vault must set enable_rbac_authorization = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
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
	helpers.is_not_true(r.block, "enable_rbac_authorization")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not set enable_rbac_authorization = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
