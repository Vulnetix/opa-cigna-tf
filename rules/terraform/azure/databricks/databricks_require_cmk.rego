# Intent: Databricks premium workspaces must enable customer-managed key encryption.
# Reference: Cigna/confectionery Databricks CMK rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_dbx_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-DBX-01",
	"name": "Databricks premium workspaces must enable customer-managed key encryption",
	"description": "azurerm_databricks_workspace on sku = premium must set customer_managed_key_enabled = true.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/databricks/security/encryption-at-rest",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "databricks"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_databricks_workspace")
	helpers.string_attr(r.block, "sku") == "premium"
	helpers.is_not_true(r.block, "customer_managed_key_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Databricks workspace %q (premium) does not enable customer-managed keys.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
