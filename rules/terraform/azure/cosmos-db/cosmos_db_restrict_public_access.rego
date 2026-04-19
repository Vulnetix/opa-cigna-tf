# Intent: Cosmos DB must disable public network access.
# Reference: Cigna/confectionery Cosmos DB public access rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_cosmos_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-COSMOS-01",
	"name": "Cosmos DB must disable public network access",
	"description": "azurerm_cosmosdb_account must set public_network_access_enabled = false.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cosmos-db"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_cosmosdb_account")
	helpers.is_not_true(r.block, "public_network_access_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cosmos DB account %q does not disable public network access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
