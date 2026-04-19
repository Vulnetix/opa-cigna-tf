# Intent: Storage accounts must enable HTTPS traffic only.
# Reference: Cigna/confectionery Storage HTTPS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_sa_02

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-SA-02",
	"name": "Storage accounts must enable HTTPS traffic only",
	"description": "azurerm_storage_account must set enable_https_traffic_only = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [319],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_storage_account")
	helpers.is_not_true(r.block, "enable_https_traffic_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not enable HTTPS traffic only.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
