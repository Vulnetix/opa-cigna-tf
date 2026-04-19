# Intent: Storage accounts must require TLS 1.2.
# Reference: Cigna/confectionery Storage TLS rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_sa_04

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-SA-04",
	"name": "Storage accounts must require TLS 1.2",
	"description": "azurerm_storage_account must set min_tls_version = \"TLS1_2\".",
	"help_uri": "https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account", "tls"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_storage_account")
	not helpers.string_attr(r.block, "min_tls_version") == "TLS1_2"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not set min_tls_version = TLS1_2.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
