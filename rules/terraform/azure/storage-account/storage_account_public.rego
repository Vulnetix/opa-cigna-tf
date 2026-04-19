# Intent: Storage accounts must not explicitly allow public blob access.
# Reference: Cigna/confectionery Storage explicit public rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_sa_03

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-SA-03",
	"name": "Storage accounts must not explicitly allow public blob access",
	"description": "azurerm_storage_account must not set allow_blob_public_access = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_storage_account")
	helpers.bool_attr(r.block, "allow_blob_public_access") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q explicitly allows public blob access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
