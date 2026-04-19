# Intent: MariaDB servers must enable geo-redundant backups.
# Reference: Cigna/confectionery MariaDB geo-redundancy rule.
# Clean-room implementation for the Vulnetix CLI input model.

package vulnetix.rules.cigna_tf_az_db_01

import rego.v1
import data.vulnetix.cigna_tf.helpers

metadata := {
	"id": "CIGNA-TF-AZ-DB-01",
	"name": "MariaDB servers must enable geo-redundant backups",
	"description": "azurerm_mariadb_server must set geo_redundant_backup_enabled = true (Basic SKUs exempt).",
	"help_uri": "https://learn.microsoft.com/en-us/azure/mariadb/concepts-backup",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "database"],
}

findings contains finding if {
	some r in helpers.resources("azurerm_mariadb_server")
	not _is_basic(r.block)
	helpers.is_not_true(r.block, "geo_redundant_backup_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MariaDB server %q does not enable geo-redundant backups.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": helpers.line_of(r.content, r.offset),
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_basic(block) if {
	sku := helpers.string_attr(block, "sku_name")
	startswith(sku, "B")
}
